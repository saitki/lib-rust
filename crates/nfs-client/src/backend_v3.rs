//! Backend NFSv3 para la capa VFS.

use nfs_proto::nfs3::{self, CreateHow3, Nfs3, NfsFh3, Sattr3};
use nfs_proto::Bytes;

use crate::attr::{Attr, DirEntry, SetAttr, StatVfs};
use crate::backend::{clamp_pref, Backend, ObjId, OpenFile, OpenOpts};
use crate::error::NfsError;

/// Backend que habla NFSv3.
pub struct V3Backend {
    nfs: Nfs3,
    rsize: u32,
    wsize: u32,
}

impl V3Backend {
    /// Crea el backend y negocia rsize/wsize con `FSINFO` sobre el fh raíz.
    pub fn new(mut nfs: Nfs3, root: &ObjId) -> Result<Self, NfsError> {
        let (rsize, wsize) = match nfs.fsinfo(&NfsFh3::new(root.clone())) {
            Ok(info) => (clamp_pref(info.rtpref), clamp_pref(info.wtpref)),
            Err(_) => (64 * 1024, 64 * 1024),
        };
        Ok(Self { nfs, rsize, wsize })
    }

    fn fh(id: &ObjId) -> NfsFh3 {
        NfsFh3::new(id.clone())
    }
}

impl Backend for V3Backend {
    fn version(&self) -> u32 {
        3
    }
    fn pref_read(&self) -> u32 {
        self.rsize
    }
    fn pref_write(&self) -> u32 {
        self.wsize
    }

    fn getattr(&mut self, fh: &ObjId) -> Result<Attr, NfsError> {
        Ok(Attr::from_fattr3(&self.nfs.getattr(&Self::fh(fh))?))
    }

    fn lookup(&mut self, dir: &ObjId, name: &str) -> Result<(ObjId, Attr), NfsError> {
        let res = self.nfs.lookup(&Self::fh(dir), name)?;
        let attr = match res.obj_attributes {
            Some(a) => Attr::from_fattr3(&a),
            None => Attr::from_fattr3(&self.nfs.getattr(&res.object)?),
        };
        Ok((res.object.data, attr))
    }

    fn open(&mut self, dir: &ObjId, name: &str, opts: OpenOpts) -> Result<OpenFile, NfsError> {
        let fh = if opts.create {
            let how = if opts.exclusive {
                CreateHow3::Guarded(Sattr3 {
                    mode: Some(opts.mode),
                    ..Sattr3::unchanged()
                })
            } else {
                CreateHow3::Unchecked(Sattr3 {
                    mode: Some(opts.mode),
                    ..Sattr3::unchanged()
                })
            };
            self.nfs
                .create(&Self::fh(dir), name, how)?
                .obj
                .ok_or(NfsError::Proto(nfs_proto::ProtoError::Protocol(
                    "CREATE no devolvió file handle",
                )))?
                .data
        } else {
            self.nfs.lookup(&Self::fh(dir), name)?.object.data
        };
        Ok(OpenFile {
            fh,
            stateid: None,
            writable: opts.write,
        })
    }

    fn close(&mut self, _file: &OpenFile) -> Result<(), NfsError> {
        Ok(()) // NFSv3 no tiene estado de apertura.
    }

    fn pread(
        &mut self,
        file: &OpenFile,
        offset: u64,
        count: u32,
    ) -> Result<(Bytes, bool), NfsError> {
        let res = self.nfs.read(&Self::fh(&file.fh), offset, count)?;
        Ok((res.data, res.eof))
    }

    fn pwrite(&mut self, file: &OpenFile, offset: u64, data: Bytes) -> Result<u32, NfsError> {
        let res = self
            .nfs
            .write(&Self::fh(&file.fh), offset, nfs3::UNSTABLE, data)?;
        Ok(res.count)
    }

    fn commit(&mut self, file: &OpenFile) -> Result<(), NfsError> {
        self.nfs.commit(&Self::fh(&file.fh), 0, 0)?;
        Ok(())
    }

    fn mkdir(&mut self, dir: &ObjId, name: &str, mode: u32) -> Result<ObjId, NfsError> {
        let attrs = Sattr3 {
            mode: Some(mode),
            ..Sattr3::unchanged()
        };
        let res = self.nfs.mkdir(&Self::fh(dir), name, attrs)?;
        match res.obj {
            Some(fh) => Ok(fh.data),
            None => Ok(self.nfs.lookup(&Self::fh(dir), name)?.object.data),
        }
    }

    fn rmdir(&mut self, dir: &ObjId, name: &str) -> Result<(), NfsError> {
        self.nfs.rmdir(&Self::fh(dir), name)?;
        Ok(())
    }

    fn remove(&mut self, dir: &ObjId, name: &str) -> Result<(), NfsError> {
        self.nfs.remove(&Self::fh(dir), name)?;
        Ok(())
    }

    fn rename(
        &mut self,
        from_dir: &ObjId,
        from_name: &str,
        to_dir: &ObjId,
        to_name: &str,
    ) -> Result<(), NfsError> {
        self.nfs
            .rename(&Self::fh(from_dir), from_name, &Self::fh(to_dir), to_name)?;
        Ok(())
    }

    fn symlink(&mut self, dir: &ObjId, name: &str, target: &str) -> Result<(), NfsError> {
        self.nfs
            .symlink(&Self::fh(dir), name, target, Sattr3::unchanged())?;
        Ok(())
    }

    fn readlink(&mut self, fh: &ObjId) -> Result<String, NfsError> {
        Ok(self.nfs.readlink(&Self::fh(fh))?.data)
    }

    fn link(&mut self, fh: &ObjId, dir: &ObjId, name: &str) -> Result<(), NfsError> {
        self.nfs.link(&Self::fh(fh), &Self::fh(dir), name)?;
        Ok(())
    }

    fn setattr(&mut self, fh: &ObjId, attr: &SetAttr) -> Result<(), NfsError> {
        self.nfs.setattr(&Self::fh(fh), attr.to_sattr3(), None)?;
        Ok(())
    }

    fn readdir(&mut self, dir: &ObjId) -> Result<Vec<DirEntry>, NfsError> {
        let mut out = Vec::new();
        let mut cookie = 0u64;
        let mut verf = [0u8; 8];
        loop {
            let page = self
                .nfs
                .readdirplus(&Self::fh(dir), cookie, verf, 8192, 32768)?;
            verf = page.cookieverf;
            let empty = page.entries.is_empty();
            for e in &page.entries {
                out.push(DirEntry {
                    name: e.name.clone(),
                    fileid: e.fileid,
                    attr: e.name_attributes.as_ref().map(Attr::from_fattr3),
                });
                cookie = e.cookie;
            }
            if page.eof || empty {
                break;
            }
        }
        Ok(out)
    }

    fn statvfs(&mut self, fh: &ObjId) -> Result<StatVfs, NfsError> {
        let s = self.nfs.fsstat(&Self::fh(fh))?;
        Ok(StatVfs {
            block_size: 1,
            total_blocks: s.tbytes,
            free_blocks: s.fbytes,
            avail_blocks: s.abytes,
            total_files: s.tfiles,
            free_files: s.ffiles,
            avail_files: s.afiles,
        })
    }

    fn access(&mut self, fh: &ObjId, mask: u32) -> Result<u32, NfsError> {
        Ok(self.nfs.access(&Self::fh(fh), mask)?.access)
    }
}
