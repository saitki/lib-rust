//! Backend NFSv4.0 para la capa VFS.

use nfs_proto::nfs4::{
    self, Nfs4, NfsFh4, SetAttr4, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_ACCESS_READ,
    OPEN4_SHARE_ACCESS_WRITE,
};
use nfs_proto::Bytes;

use crate::attr::{Attr, DirEntry, SetAttr, StatVfs};
use crate::backend::{Backend, LockToken, ObjId, OpenFile, OpenOpts};
use crate::error::NfsError;

/// Backend que habla NFSv4.0.
pub struct V4Backend {
    nfs: Nfs4,
    rsize: u32,
    wsize: u32,
}

impl V4Backend {
    /// Crea el backend con tamaños de read/write por defecto.
    pub fn new(nfs: Nfs4) -> Self {
        Self {
            nfs,
            rsize: 256 * 1024,
            wsize: 256 * 1024,
        }
    }

    fn fh(id: &ObjId) -> NfsFh4 {
        NfsFh4::new(id.clone())
    }
}

impl Backend for V4Backend {
    fn version(&self) -> u32 {
        4
    }
    fn pref_read(&self) -> u32 {
        self.rsize
    }
    fn pref_write(&self) -> u32 {
        self.wsize
    }

    fn getattr(&mut self, fh: &ObjId) -> Result<Attr, NfsError> {
        Ok(Attr::from_fattr4(&self.nfs.getattr(&Self::fh(fh))?))
    }

    fn lookup(&mut self, dir: &ObjId, name: &str) -> Result<(ObjId, Attr), NfsError> {
        let (fh, attrs) = self.nfs.lookup(&Self::fh(dir), name)?;
        Ok((fh.data, Attr::from_fattr4(&attrs)))
    }

    fn open(&mut self, dir: &ObjId, name: &str, opts: OpenOpts) -> Result<OpenFile, NfsError> {
        let share = if opts.write && opts.create {
            OPEN4_SHARE_ACCESS_BOTH
        } else if opts.write {
            OPEN4_SHARE_ACCESS_WRITE
        } else {
            OPEN4_SHARE_ACCESS_READ
        };
        let res = self.nfs.open(&Self::fh(dir), name, share, opts.create)?;
        Ok(OpenFile {
            fh: res.fh.data,
            stateid: Some(res.stateid),
            writable: opts.write,
        })
    }

    fn close(&mut self, file: &OpenFile) -> Result<(), NfsError> {
        if let Some(stateid) = &file.stateid {
            self.nfs.close(&Self::fh(&file.fh), stateid)?;
        }
        Ok(())
    }

    fn pread(
        &mut self,
        file: &OpenFile,
        offset: u64,
        count: u32,
    ) -> Result<(Bytes, bool), NfsError> {
        let stateid = file.stateid.unwrap_or_default();
        let res = self
            .nfs
            .read(&Self::fh(&file.fh), &stateid, offset, count)?;
        Ok((res.data, res.eof))
    }

    fn pwrite(&mut self, file: &OpenFile, offset: u64, data: Bytes) -> Result<u32, NfsError> {
        let stateid = file.stateid.unwrap_or_default();
        Ok(self
            .nfs
            .write(&Self::fh(&file.fh), &stateid, offset, nfs4::UNSTABLE4, data)?)
    }

    fn commit(&mut self, file: &OpenFile) -> Result<(), NfsError> {
        self.nfs.commit(&Self::fh(&file.fh), 0, 0)?;
        Ok(())
    }

    fn mkdir(&mut self, dir: &ObjId, name: &str, _mode: u32) -> Result<ObjId, NfsError> {
        Ok(self.nfs.mkdir(&Self::fh(dir), name)?.data)
    }

    fn rmdir(&mut self, dir: &ObjId, name: &str) -> Result<(), NfsError> {
        self.nfs.remove(&Self::fh(dir), name)?;
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
        self.nfs.symlink(&Self::fh(dir), name, target)?;
        Ok(())
    }

    fn readlink(&mut self, fh: &ObjId) -> Result<String, NfsError> {
        Ok(self.nfs.readlink(&Self::fh(fh))?)
    }

    fn link(&mut self, fh: &ObjId, dir: &ObjId, name: &str) -> Result<(), NfsError> {
        self.nfs.link(&Self::fh(fh), &Self::fh(dir), name)?;
        Ok(())
    }

    fn setattr(&mut self, fh: &ObjId, attr: &SetAttr) -> Result<(), NfsError> {
        self.nfs.setattr(
            &Self::fh(fh),
            &SetAttr4 {
                mode: attr.mode,
                size: attr.size,
            },
        )?;
        Ok(())
    }

    fn readdir(&mut self, dir: &ObjId) -> Result<Vec<DirEntry>, NfsError> {
        let mut out = Vec::new();
        let mut cookie = 0u64;
        let mut verf = [0u8; 8];
        loop {
            let page = self.nfs.readdir(&Self::fh(dir), cookie, verf, 32768)?;
            verf = page.cookieverf;
            let empty = page.entries.is_empty();
            for e in &page.entries {
                out.push(DirEntry {
                    name: e.name.clone(),
                    fileid: e.attrs.fileid.unwrap_or(0),
                    attr: Some(Attr::from_fattr4(&e.attrs)),
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
        let a = self.nfs.statvfs(&Self::fh(fh))?;
        Ok(StatVfs {
            block_size: 1,
            total_blocks: a.space_total.unwrap_or(0),
            free_blocks: a.space_free.unwrap_or(0),
            avail_blocks: a.space_avail.unwrap_or(0),
            total_files: a.files_total.unwrap_or(0),
            free_files: a.files_free.unwrap_or(0),
            avail_files: a.files_avail.unwrap_or(0),
        })
    }

    fn access(&mut self, fh: &ObjId, mask: u32) -> Result<u32, NfsError> {
        Ok(self.nfs.access(&Self::fh(fh), mask)?)
    }

    fn lock(
        &mut self,
        file: &OpenFile,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<LockToken, NfsError> {
        let open_stateid = file.stateid.unwrap_or_default();
        let grant = self.nfs.lock(
            &Self::fh(&file.fh),
            &open_stateid,
            offset,
            length,
            exclusive,
        )?;
        Ok(LockToken::V4 {
            grant,
            offset,
            length,
        })
    }

    fn unlock(&mut self, file: &OpenFile, token: &LockToken) -> Result<(), NfsError> {
        if let LockToken::V4 {
            grant,
            offset,
            length,
        } = token
        {
            self.nfs
                .unlock(&Self::fh(&file.fh), grant, *offset, *length)?;
        }
        Ok(())
    }

    fn test_lock(
        &mut self,
        file: &OpenFile,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Result<bool, NfsError> {
        Ok(self
            .nfs
            .test_lock(&Self::fh(&file.fh), offset, length, exclusive)?)
    }
}
