# -*- coding: utf-8 -*-
"""问题 27-3 的复原实验：两种排序键是否可能给出不同顺序？

报告说法：预取排序用「扣减后的热度」，而「够格预取」的门槛用「扣减前的热度」，
两个口径不一致 ⇒ 刷新顺序轻微失序。

本实验穷举所有可能进入 to_prefetch 的候选集合（门槛：扣减前 hits >= 2），
分别按「扣减前」与「扣减后」排序，比较顺序是否相同。
"""


def sat_sub1(x: int) -> int:
    return x - 1 if x > 1 else 0


def orders(keys):
    """返回 (按扣减前排序, 按扣减后排序) 的 key 序列。"""
    # 门槛用的是扣减前：hits >= 2
    eligible = [k for k in keys if k[1] >= 2]
    by_before = sorted(eligible, key=lambda k: -k[1])
    by_after = sorted(eligible, key=lambda k: -sat_sub1(k[1]))
    return [k[0] for k in by_before], [k[0] for k in by_after]


def main():
    import itertools

    values = range(0, 8)
    bad = 0
    checked = 0

    # 穷举 1~4 个条目（名字 a,b,c,d），热度取值 0..7
    for n in range(1, 5):
        names = "abcd"[:n]
        for combo in itertools.product(values, repeat=n):
            keys = list(zip(names, combo))
            checked += 1
            before, after = orders(keys)
            if before != after:
                bad += 1
                if bad <= 5:
                    print("发现顺序不同：", keys, "->", before, "vs", after)

    print(f"共检查 {checked} 种组合，顺序不一致的有 {bad} 种")
    if bad == 0:
        print("结论：两者排序结果恒等 => 27-3 描述的『错序』不成立")
        print("原因：x.saturating_sub(1) 单调非减，唯一并列点 hits=1 不够格入选")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
