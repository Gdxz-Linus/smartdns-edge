//! 字节 ↔ 值的直接转换。
//!
//! 🔐 P2 修复：原来的边界是 `impl<T: Copy + Sized> MemBytes<T> for T` —— 于是 `char`、`bool`、
//! 枚举这些**有非法位模式**的类型也能用。比如 `bool` 只允许 0/1，用别的字节构造出来就是
//! 未定义行为（UB）；`char` 同理（必须是合法 Unicode 标量）。
//!
//! 现在用「封闭 trait」把可用类型锁死在无非法位模式的 POD 数值类型上：
//! 借用者没法为自定义类型实现（sealed），写错类型在编译期就报错，不会再偷偷 UB。

pub trait MemBytes<T: Copy + Sized> {
    fn mem_size() -> usize {
        std::mem::size_of::<T>()
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((self as *const Self) as *const u8, std::mem::size_of::<T>())
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

/// 封闭标记：只有本文件里列出的类型才算「任意位模式都合法」。
mod sealed {
    pub trait Sealed {}

    macro_rules! impl_sealed {
        ($($t:ty),* $(,)?) => { $( impl Sealed for $t {} )* };
    }

    impl_sealed!(
        u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
    );
    // 字节数组也是"任意内容都合法"的
    impl<const N: usize> Sealed for [u8; N] {}
}

/// 「任意位模式都是合法值」的 POD 类型（整数 / 浮点 / 字节数组）。
pub trait PodValue: Copy + Sized + sealed::Sealed {}

macro_rules! impl_pod {
    ($($t:ty),* $(,)?) => { $( impl PodValue for $t {} )* };
}

impl_pod!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
);
impl<const N: usize> PodValue for [u8; N] {}

// 🔐 P2：边界从 `T: Copy` 收紧为 `T: PodValue` —— char / bool / 枚举 不再能用
impl<T: PodValue> MemBytes<T> for T {}

#[cfg(test)]
mod tests {
    use crate::infra::mem_bytes::MemBytes;

    #[test]
    fn test_as_bytes() {
        let a: u32 = 97;
        assert_eq!(a.as_bytes(), &[97, 0, 0, 0]);
    }

    #[test]
    fn test_from_bytes() {
        let a: u32 = u32::from_bytes(&[97, 0, 0, 0]);
        assert_eq!(a, 97);

        // 浮点也是「任意位模式都合法」的
        let f = f32::from_bytes(&0.5f32.to_le_bytes());
        assert_eq!(f, 0.5);

        // 字节数组
        let arr = <[u8; 4]>::from_bytes(&[1, 2, 3, 4]);
        assert_eq!(arr, [1, 2, 3, 4]);
    }

    #[test]
    fn test_try_from_bytes() {
        let invalid_bytes = &[97, 0];
        assert_eq!(u32::try_from_bytes(invalid_bytes), None);
        assert_eq!(u32::try_from_bytes(&[97, 0, 0, 0]), Some(97));
    }
}
