use crate::installers::inno::compression::Compression;
use crate::installers::inno::read::chunk::{InnoChunkReader, INNO_CHUNK_SIZE};
use crate::installers::inno::read::crc32::Crc32Reader;
use crate::installers::inno::read::decoder::Decoder;
use crate::installers::inno::version::KnownVersion;
use crate::installers::inno::InnoError;
use crate::installers::utils::read_lzma_stream_header;
use byteorder::{ReadBytesExt, LE};
use flate2::read::ZlibDecoder;
use liblzma::read::XzDecoder;
use std::io::{Error, ErrorKind, Read, Result, Take};

pub struct InnoBlockReader<R: Read> {
    inner: Decoder<InnoChunkReader<Take<R>>>,
}

impl<R: Read> InnoBlockReader<R> {
    pub fn get(mut inner: R, version: &KnownVersion) -> Result<Self> {
        let compression = Self::read_header(&mut inner, version)?;

        let mut chunk_reader = InnoChunkReader::new(inner.take(u64::from(*compression)));

        Ok(Self {
            inner: match compression {
                Compression::LZMA1(_) => {
                    let stream = read_lzma_stream_header(&mut chunk_reader)?;
                    Decoder::LZMA1(XzDecoder::new_stream(chunk_reader, stream))
                }
                Compression::Zlib(_) => Decoder::Zlib(ZlibDecoder::new(chunk_reader)),
                Compression::Stored(_) => Decoder::Stored(chunk_reader),
            },
        })
    }

    pub fn read_header(reader: &mut R, version: &KnownVersion) -> Result<Compression> {
        let expected_crc32 = reader.read_u32::<LE>()?;

        let mut actual_crc32 = Crc32Reader::new(reader);

        let compression = if *version >= (4, 0, 9) {
            let size = actual_crc32.read_u32::<LE>()?;
            let compressed = actual_crc32.read_u8()? != 0;

            if compressed {
                if *version >= (4, 1, 6) {
                    Compression::LZMA1(size)
                } else {
                    Compression::Zlib(size)
                }
            } else {
                Compression::Stored(size)
            }
        } else {
            let compressed_size = actual_crc32.read_u32::<LE>()?;
            let uncompressed_size = actual_crc32.read_u32::<LE>()?;

            let mut stored_size = if compressed_size == u32::MAX {
                Compression::Stored(uncompressed_size)
            } else {
                Compression::Zlib(compressed_size)
            };

            // Add the size of a CRC32 checksum for each 4KiB sub-block
            *stored_size += stored_size.div_ceil(u32::from(INNO_CHUNK_SIZE)) * 4;

            stored_size
        };

        let actual_crc32 = actual_crc32.finalize();
        if actual_crc32 != expected_crc32 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                InnoError::CrcChecksumMismatch {
                    actual: actual_crc32,
                    expected: expected_crc32,
                },
            ));
        }

        Ok(compression)
    }
}

impl<R: Read> Read for InnoBlockReader<R> {
    fn read(&mut self, dest: &mut [u8]) -> Result<usize> {
        self.inner.read(dest)
    }
}
