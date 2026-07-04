pub trait MemBytes<T: Copy + Sized> {
    fn mem_size() -> usize {
        std::mem::size_of::<T>()
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                std::mem::size_of::<T>(),
            )
        }
    }

    fn from_bytes(bytes: &[u8]) -> T {
        assert!(
            bytes.len() >= std::mem::size_of::<T>(),
            "buffer length ({}) is smaller than type size ({})",
            bytes.len(),
            std::mem::size_of::<T>()
        );
        unsafe {
            // 🌟 核心修复：改用 read_unaligned + Copy 约束
            // 彻底杜绝非对齐指针读取导致的未定义行为 (UB) 和内存二次释放 (Double Free) 隐患
            std::ptr::read_unaligned(bytes.as_ptr() as *const T)
        }
    }

    /// 尝试从字节切片反序列化，如果字节长度不足则返回 None
    fn try_from_bytes(bytes: &[u8]) -> Option<T> {
        if bytes.len() < std::mem::size_of::<T>() {
            None
        } else {
            Some(Self::from_bytes(bytes))
        }
    }
}

// 🌟 核心修复：仅为实现 Copy 特性的 POD 基础数据类型实现该 Trait
impl<T: Copy + Sized> MemBytes<T> for T {}

#[cfg(test)]
mod tests {
    use crate::infra::mem_bytes::MemBytes;

    #[test]
    fn test_as_bytes() {
        let a = 'a';
        assert_eq!(a.as_bytes(), &[97, 0, 0, 0]);
    }

    #[test]
    fn test_from_bytes() {
        let a = char::from_bytes(&[97, 0, 0, 0]);
        assert_eq!(a, 'a');
    }

    #[test]
    fn test_try_from_bytes() {
        let invalid_bytes = &[97, 0];
        assert_eq!(char::try_from_bytes(invalid_bytes), None);
    }
}