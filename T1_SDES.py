# 扩展的 S-DES 实现，包含：
# - 二进制 8-bit 加/解密（encrypt / decrypt）
# - ASCII 字符串的分组加密/解密接口
# - 暴力破解（单/多对明密文）支持多线程
# - 密钥碰撞检测工具（检查多个不同密钥是否对同一明文产生相同密文）
#
# 代码风格：函数化、变量命名语义化、必要注释

from typing import List, Tuple, Dict
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class SDES:
    def __init__(self):
        # 置换表定义（根据实验要求）
        self.IP = [2, 6, 3, 1, 4, 8, 5, 7]
        self.IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
        self.P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        self.P8 = [6, 3, 7, 4, 8, 5, 10, 9]
        self.P4 = [2, 4, 3, 1]
        self.EP = [4, 1, 2, 3, 2, 3, 4, 1]

        # S-Boxes（以实验要求为准）
        self.S1 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 3, 2]
        ]

        self.S2 = [
            [0, 1, 2, 3],
            [2, 0, 1, 3],
            [3, 0, 1, 0],
            [2, 1, 0, 3]
        ]

        # 用于记录过程日志（供 GUI 或测试输出）
        self.process_log: List[str] = []

    # ---------------------------
    # 日志管理
    # ---------------------------
    def log(self, message: str) -> None:
        """把一条日志追加到内部日志列表（保留用于 GUI 显示或测试输出）"""
        self.process_log.append(message)
        # 不在这里打印到 stdout（GUI 将显示日志），但保留打印以便命令行运行也能看到
        # print(message)

    def reset_log(self) -> None:
        """重置日志（每次操作前调用）"""
        self.process_log = []

    def get_log(self) -> str:
        """返回整段日志文本（换行分隔）"""
        return "\n".join(self.process_log)

    # ---------------------------
    # 基本位操作函数
    # ---------------------------
    @staticmethod
    def _permute_bits(bitstring: str, table: List[int]) -> str:
        """按给定置换表对位串进行置换（table 使用 1-based 索引）"""
        return ''.join(bitstring[i - 1] for i in table)

    def permute(self, data: str, table: List[int]) -> str:
        """封装的置换，带日志"""
        result = self._permute_bits(data, table)
        self.log(f"置换 {table} 应用于 {data} -> {result}")
        return result

    @staticmethod
    def left_shift(bits: str, shift: int) -> str:
        """循环左移 bits 字符串（shift >= 0）"""
        return bits[shift:] + bits[:shift]

    # ---------------------------
    # 密钥生成
    # ---------------------------
    def generate_subkeys(self, key10: str) -> Tuple[str, str]:
        """
        从 10-bit 密钥生成两个子密钥 K1、K2
        返回 (k1, k2)，每个为 8-bit 字符串（P8 后得到）
        """
        self.log(f"生成子密钥：原始 10-bit 密钥 = {key10}")

        # P10
        p10_result = self.permute(key10, self.P10)
        self.log(f"P10 结果 = {p10_result}")

        left = p10_result[:5]
        right = p10_result[5:]
        self.log(f"P10 分割：L={left} R={right}")

        # 左移 1 -> K1
        left1 = self.left_shift(left, 1)
        right1 = self.left_shift(right, 1)
        combined1 = left1 + right1
        k1 = self.permute(combined1, self.P8)
        self.log(f"左移1后组合并经 P8 -> K1 = {k1}")

        # 左移 2（在 left1/right1 基础上）-> K2
        left2 = self.left_shift(left1, 2)
        right2 = self.left_shift(right1, 2)
        combined2 = left2 + right2
        k2 = self.permute(combined2, self.P8)
        self.log(f"左移2后组合并经 P8 -> K2 = {k2}")

        return k1, k2

    # ---------------------------
    # S-Box 查找
    # ---------------------------
    def s_box_lookup(self, input_bits: str, sbox: List[List[int]], name: str) -> str:
        """
        input_bits: 4-bit 字符串
        sbox: 4x4 表
        返回 2-bit 字符串
        """
        row = int(input_bits[0] + input_bits[3], 2)
        col = int(input_bits[1] + input_bits[2], 2)
        val = sbox[row][col]
        out_bits = format(val, '02b')
        self.log(f"{name} 查表: 输入={input_bits} 行={row} 列={col} 值={val} -> {out_bits}")
        return out_bits

    # ---------------------------
    # 轮函数 f
    # ---------------------------
    def f_function(self, right4: str, subkey8: str) -> str:
        """
        right4: 4-bit 字符串
        subkey8: 8-bit 子密钥
        返回：4-bit 字符串（经 P4）
        """
        self.log(f"F 函数输入：R={right4}, subkey={subkey8}")
        # 扩展置换 EP（4 -> 8）
        expanded = self.permute(right4, self.EP)
        self.log(f"EP 结果 = {expanded}")
        # XOR with subkey
        xor_result = ''.join('1' if a != b else '0' for a, b in zip(expanded, subkey8))
        self.log(f"与子密钥异或结果 = {xor_result}")
        s1_in = xor_result[:4]
        s2_in = xor_result[4:]
        s1_out = self.s_box_lookup(s1_in, self.S1, 'S1')
        s2_out = self.s_box_lookup(s2_in, self.S2, 'S2')
        combined = s1_out + s2_out
        self.log(f"S 盒合并输出 = {combined}")
        p4_result = self.permute(combined, self.P4)
        self.log(f"P4 结果 = {p4_result}")
        return p4_result

    # ---------------------------
    # 基本加密 / 解密（对单个 8-bit 二进制块）
    # ---------------------------
    def encrypt(self, plaintext8: str, key10: str) -> str:
        """
        对单个 8-bit 明文位串进行 S-DES 加密，返回 8-bit 密文位串。
        plaintext8 / key10 都以字符串形式传入（'10101010' / '1010000010'）
        """
        self.reset_log()
        self.log(f"开始加密：明文={plaintext8} 密钥={key10}")

        k1, k2 = self.generate_subkeys(key10)

        # IP
        ip = self.permute(plaintext8, self.IP)
        self.log(f"IP 后 = {ip}")

        left, right = ip[:4], ip[4:]
        self.log(f"初始左右分块 L0={left} R0={right}")

        # 轮 1 (使用 K1)
        self.log("----- 轮 1 (使用 K1) -----")
        f1 = self.f_function(right, k1)
        left1 = ''.join('1' if a != b else '0' for a, b in zip(left, f1))
        right1 = right
        self.log(f"轮1 结果 L1={left1} R1={right1}")

        # 交换
        left_after_swap, right_after_swap = right1, left1
        self.log(f"交换后 L'={left_after_swap} R'={right_after_swap}")

        # 轮 2 (使用 K2)
        self.log("----- 轮 2 (使用 K2) -----")
        f2 = self.f_function(right_after_swap, k2)
        left2 = ''.join('1' if a != b else '0' for a, b in zip(left_after_swap, f2))
        right2 = right_after_swap
        self.log(f"轮2 结果 L2={left2} R2={right2}")

        preoutput = left2 + right2
        self.log(f"合并前输出 = {preoutput}")

        # IP^-1
        ciphertext8 = self.permute(preoutput, self.IP_INV)
        self.log(f"逆初始置换 IP^-1 后密文 = {ciphertext8}")
        self.log("加密完成")
        return ciphertext8

    def decrypt(self, ciphertext8: str, key10: str) -> str:
        """
        对单个 8-bit 密文位串进行 S-DES 解密，返回 8-bit 明文位串。
        核心思路：生成 K1,K2 并反序使用（K2 -> 第一轮，K1 -> 第二轮）
        """
        self.reset_log()
        self.log(f"开始解密：密文={ciphertext8} 密钥={key10}")

        k1, k2 = self.generate_subkeys(key10)

        # IP
        ip = self.permute(ciphertext8, self.IP)
        self.log(f"IP 后 = {ip}")

        left, right = ip[:4], ip[4:]
        self.log(f"初始左右分块 L0={left} R0={right}")

        # 第1轮（使用 K2）
        self.log("----- 解密轮 1 (使用 K2) -----")
        f1 = self.f_function(right, k2)
        left1 = ''.join('1' if a != b else '0' for a, b in zip(left, f1))
        right1 = right
        self.log(f"解密轮1 结果 L1={left1} R1={right1}")

        # 交换
        left_after_swap, right_after_swap = right1, left1
        self.log(f"交换后 L'={left_after_swap} R'={right_after_swap}")

        # 第2轮（使用 K1）
        self.log("----- 解密轮 2 (使用 K1) -----")
        f2 = self.f_function(right_after_swap, k1)
        left2 = ''.join('1' if a != b else '0' for a, b in zip(left_after_swap, f2))
        right2 = right_after_swap
        self.log(f"解密轮2 结果 L2={left2} R2={right2}")

        preoutput = left2 + right2
        self.log(f"合并前输出 = {preoutput}")

        # IP^-1
        plaintext8 = self.permute(preoutput, self.IP_INV)
        self.log(f"逆初始置换 IP^-1 后明文 = {plaintext8}")
        self.log("解密完成")
        return plaintext8

    # ---------------------------
    # 扩展功能：ASCII 字符串处理（第3关）
    # ---------------------------
    @staticmethod
    def byte_to_bits(byte_val: int) -> str:
        """将 0-255 的整数转成 8 位二进制字符串"""
        return format(byte_val, '08b')

    @staticmethod
    def bits_to_byte(bits8: str) -> int:
        """将 8 位二进制字符串转回整数 0-255"""
        return int(bits8, 2)

    def encrypt_ascii_to_bitblocks(self, plaintext: str, key10: str) -> List[str]:
        """
        把 ASCII 字符串 plaintext 分组（每字符 1 byte / 8 bit），对每组使用 encrypt，
        返回每组 8-bit 的密文字符串列表。
        """
        ciphertext_blocks: List[str] = []
        for ch in plaintext:
            b = self.byte_to_bits(ord(ch))
            c_block = self.encrypt(b, key10)
            ciphertext_blocks.append(c_block)
        return ciphertext_blocks

    def decrypt_bitblocks_to_ascii(self, ciphertext_blocks: List[str], key10: str) -> str:
        """
        将 8-bit 密文块列表解密并还原为 ASCII 字符串（可能有乱码）
        """
        chars: List[str] = []
        for bits in ciphertext_blocks:
            p_bits = self.decrypt(bits, key10)
            chars.append(chr(self.bits_to_byte(p_bits)))
        return ''.join(chars)

    # ---------------------------
    # 暴力破解（第4关）
    # ---------------------------
    def brute_force_search_single_pair(self, plaintext8: str, ciphertext8: str, use_threads: bool = True,
                                       max_workers: int = 8) -> Tuple[List[str], float]:
        """
        对单个明/密文（单个 8-bit 块）进行暴力破解：遍历所有 10-bit 密钥，返回匹配的密钥列表。
        返回 (matching_key_list, elapsed_seconds)
        key 表示为 10-bit 字符串。
        """
        start = time.perf_counter()
        matches: List[str] = []

        def test_key(k_int: int) -> Tuple[int, bool]:
            k_bin = format(k_int, '010b')
            c = self.encrypt(plaintext8, k_bin)
            return k_int, (c == ciphertext8)

        if use_threads:
            # 使用线程池并行化（因为每次 encrypt 本身比较轻量，线程数量以 CPU 为准）
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(test_key, k): k for k in range(1024)}
                for fut in as_completed(futures):
                    k_int, is_match = fut.result()
                    if is_match:
                        matches.append(format(k_int, '010b'))
        else:
            for k in range(1024):
                k_bin = format(k, '010b')
                c = self.encrypt(plaintext8, k_bin)
                if c == ciphertext8:
                    matches.append(k_bin)

        elapsed = time.perf_counter() - start
        self.log(f"暴力破解（单对）完成，耗时 {elapsed:.6f} 秒，匹配密钥数 = {len(matches)}")
        return matches, elapsed

    def brute_force_search_multiple_pairs(self, pairs: List[Tuple[str, str]], use_threads: bool = True,
                                          max_workers: int = 8) -> Tuple[List[str], float]:
        """
        对多个明/密文本对进行联合暴力破解（密钥必须同时满足所有对）。
        pairs: List of (plaintext8, ciphertext8)
        返回 (matching_key_list, elapsed_seconds)
        """
        start = time.perf_counter()
        matches: List[str] = []

        def test_key(k_int: int) -> Tuple[int, bool]:
            k_bin = format(k_int, '010b')
            ok_all = True
            for p8, c8 in pairs:
                if self.encrypt(p8, k_bin) != c8:
                    ok_all = False
                    break
            return k_int, ok_all

        if use_threads:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(test_key, k): k for k in range(1024)}
                for fut in as_completed(futures):
                    k_int, ok = fut.result()
                    if ok:
                        matches.append(format(k_int, '010b'))
        else:
            for k in range(1024):
                k_bin = format(k, '010b')
                ok_all = True
                for p8, c8 in pairs:
                    if self.encrypt(p8, k_bin) != c8:
                        ok_all = False
                        break
                if ok_all:
                    matches.append(k_bin)

        elapsed = time.perf_counter() - start
        self.log(f"暴力破解（多对）完成，耗时 {elapsed:.6f} 秒，匹配密钥数 = {len(matches)}")
        return matches, elapsed

    # ---------------------------
    # 密钥碰撞 / 覆盖分析（第5关）
    # ---------------------------
    def keys_for_plaintext_produce_cipher(self, plaintext8: str) -> Dict[str, List[str]]:
        """
        对给定明文 8-bit，枚举所有 1024 个密钥，返回字典：
        { ciphertext8 : [ key10s_that_produce_it ] }
        用于检查是否存在不同密钥导致相同密文的情况。
        """
        mapping: Dict[str, List[str]] = {}
        for k in range(1024):
            k_bin = format(k, '010b')
            c = self.encrypt(plaintext8, k_bin)
            mapping.setdefault(c, []).append(k_bin)
        # 不在此处记录日志太多信息（调用方可根据返回值处理）
        return mapping

    def analyze_collision_for_plaintext(self, plaintext8: str) -> Dict[str, List[str]]:
        """
        更语义化的封装：返回那些被多个密钥映射为同一密文的条目。
        返回字典 { ciphertext8 : [distinct_keys...] } 仅包含 len(keys)>1 的项。
        """
        mapping = self.keys_for_plaintext_produce_cipher(plaintext8)
        collisions = {c: keys for c, keys in mapping.items() if len(keys) > 1}
        self.log(f"对明文 {plaintext8} 的碰撞分析：共有 {len(collisions)} 个不同密文由多个密钥产生")
        return collisions








# #  S_DES的算法程序

# class SDES:
#     def __init__(self):
#         # 置换表定义
#         self.IP = [2, 6, 3, 1, 4, 8, 5, 7]
#         self.IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
#         self.P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
#         self.P8 = [6, 3, 7, 4, 8, 5, 10, 9]
#         self.P4 = [2, 4, 3, 1]
#         self.EP = [4, 1, 2, 3, 2, 3, 4, 1]

#         # S盒定义
#         self.S1 = [
#             [1, 0, 3, 2],
#             [3, 2, 1, 0],
#             [0, 2, 1, 3],
#             [3, 1, 3, 2]
#         ]

#         self.S2 = [
#             [0, 1, 2, 3],
#             [2, 0, 1, 3],
#             [3, 0, 1, 0],
#             [2, 1, 0, 3]
#         ]

#         # 用于记录过程
#         self.process_log = []

#     def log(self, message):
#         """记录过程日志"""
#         self.process_log.append(message)
#         print(message)

#     def reset_log(self):
#         """重置过程日志"""
#         self.process_log = []

#     def get_log(self):
#         """获取过程日志"""
#         return "\n".join(self.process_log)

#     def permute(self, data, table):
#         """置换函数"""
#         result = ''.join([data[table[i] - 1] for i in range(len(table))])
#         self.log(f"置换 [{', '.join(map(str, table))}] 应用于 {data} 得到 {result}")
#         return result

#     def left_shift(self, data, shifts):
#         """左移函数"""
#         shifted = data[shifts:] + data[:shifts]
#         self.log(f"左移 {shifts} 位: {data} → {shifted}")
#         return shifted

#     def generate_subkeys(self, key):
#         """生成子密钥"""
#         self.log(f"开始生成子密钥，原始密钥: {key}")

#         # P10置换
#         p10_key = self.permute(key, self.P10)
#         self.log(f"P10置换后: {p10_key}")

#         # 分为左右两部分
#         left = p10_key[:5]
#         right = p10_key[5:]
#         self.log(f"分为左右两部分: L={left}, R={right}")

#         # 生成K1
#         left1 = self.left_shift(left, 1)
#         right1 = self.left_shift(right, 1)
#         combined1 = left1 + right1
#         k1 = self.permute(combined1, self.P8)
#         self.log(f"生成K1: {k1}")

#         # 生成K2
#         left2 = self.left_shift(left1, 2)
#         right2 = self.left_shift(right1, 2)
#         combined2 = left2 + right2
#         k2 = self.permute(combined2, self.P8)
#         self.log(f"生成K2: {k2}")

#         return k1, k2

#     def s_box_lookup(self, input_str, s_box, name):
#         """S盒查找"""
#         # 计算行和列
#         row = int(input_str[0] + input_str[3], 2)
#         col = int(input_str[1] + input_str[2], 2)

#         # 获取值并转换为2位二进制
#         value = s_box[row][col]
#         binary = bin(value)[2:].zfill(2)

#         self.log(f"{name}盒查找: 输入={input_str}, 行={row}, 列={col}, 值={value}, 二进制={binary}")
#         return binary

#     def f_function(self, data, subkey):
#         """F函数"""
#         self.log(f"F函数: 数据={data}, 子密钥={subkey}")

#         # 扩展置换
#         expanded = self.permute(data, self.EP)
#         self.log(f"扩展置换后: {expanded}")

#         # 与子密钥异或
#         xor_result = ''.join(['1' if a != b else '0' for a, b in zip(expanded, subkey)])
#         self.log(f"与子密钥异或: {xor_result}")

#         # 分为S1和S2的输入
#         s1_input = xor_result[:4]
#         s2_input = xor_result[4:]
#         self.log(f"S盒输入: S1={s1_input}, S2={s2_input}")

#         # S盒代换
#         s1_output = self.s_box_lookup(s1_input, self.S1, 'S1')
#         s2_output = self.s_box_lookup(s2_input, self.S2, 'S2')
#         self.log(f"S盒输出: S1={s1_output}, S2={s2_output}")

#         # 合并S盒输出
#         combined = s1_output + s2_output
#         self.log(f"合并S盒输出: {combined}")

#         # P4置换
#         p4_result = self.permute(combined, self.P4)
#         self.log(f"P4置换后: {p4_result}")

#         return p4_result

#     def encrypt(self, plaintext, key):
#         """加密函数"""
#         self.reset_log()
#         self.log(f"开始加密: 明文={plaintext}, 密钥={key}")

#         # 生成子密钥
#         k1, k2 = self.generate_subkeys(key)

#         # 初始置换IP
#         ip_result = self.permute(plaintext, self.IP)
#         self.log(f"初始置换IP后: {ip_result}")

#         # 分为左右两部分
#         left, right = ip_result[:4], ip_result[4:]
#         self.log(f"分为左右两部分: L0={left}, R0={right}")

#         # 第1轮加密
#         self.log('----- 第1轮加密 -----')
#         f1 = self.f_function(right, k1)
#         new_left1 = ''.join(['1' if a != b else '0' for a, b in zip(left, f1)])
#         new_right1 = right
#         self.log(f"第1轮结果: L1={new_left1}, R1={new_right1}")

#         # 交换
#         swapped_left, swapped_right = new_right1, new_left1
#         self.log(f"交换后: L'={swapped_left}, R'={swapped_right}")

#         # 第2轮加密
#         self.log('----- 第2轮加密 -----')
#         f2 = self.f_function(swapped_right, k2)
#         new_left2 = ''.join(['1' if a != b else '0' for a, b in zip(swapped_left, f2)])
#         new_right2 = swapped_right
#         self.log(f"第2轮结果: L2={new_left2}, R2={new_right2}")

#         # 合并
#         pre_output = new_left2 + new_right2
#         self.log(f"合并结果: {pre_output}")

#         # 逆初始置换
#         ciphertext = self.permute(pre_output, self.IP_INV)
#         self.log(f"逆初始置换IP^-1后: {ciphertext}")
#         self.log(f"加密完成: 密文={ciphertext}")

#         return ciphertext

#     def decrypt(self, ciphertext, key):
#         """解密函数"""
#         self.reset_log()
#         self.log(f"开始解密: 密文={ciphertext}, 密钥={key}")

#         # 生成子密钥（解密使用相反顺序的子密钥）
#         k1, k2 = self.generate_subkeys(key)

#         # 初始置换IP
#         ip_result = self.permute(ciphertext, self.IP)
#         self.log(f"初始置换IP后: {ip_result}")

#         # 分为左右两部分
#         left, right = ip_result[:4], ip_result[4:]
#         self.log(f"分为左右两部分: L0={left}, R0={right}")

#         # 第1轮解密（使用K2）
#         self.log('----- 第1轮解密 (使用K2) -----')
#         f1 = self.f_function(right, k2)
#         new_left1 = ''.join(['1' if a != b else '0' for a, b in zip(left, f1)])
#         new_right1 = right
#         self.log(f"第1轮结果: L1={new_left1}, R1={new_right1}")

#         # 交换
#         swapped_left, swapped_right = new_right1, new_left1
#         self.log(f"交换后: L'={swapped_left}, R'={swapped_right}")

#         # 第2轮解密（使用K1）
#         self.log('----- 第2轮解密 (使用K1) -----')
#         f2 = self.f_function(swapped_right, k1)
#         new_left2 = ''.join(['1' if a != b else '0' for a, b in zip(swapped_left, f2)])
#         new_right2 = swapped_right
#         self.log(f"第2轮结果: L2={new_left2}, R2={new_right2}")

#         # 合并
#         pre_output = new_left2 + new_right2
#         self.log(f"合并结果: {pre_output}")

#         # 逆初始置换
#         plaintext = self.permute(pre_output, self.IP_INV)
#         self.log(f"逆初始置换IP^-1后: {plaintext}")
#         self.log(f"解密完成: 明文={plaintext}")

#         return plaintext

