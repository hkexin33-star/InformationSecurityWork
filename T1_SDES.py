#  S_DES的算法程序

class SDES:
    def __init__(self):
        # 置换表定义
        self.IP = [2, 6, 3, 1, 4, 8, 5, 7]
        self.IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
        self.P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        self.P8 = [6, 3, 7, 4, 8, 5, 10, 9]
        self.P4 = [2, 4, 3, 1]
        self.EP = [4, 1, 2, 3, 2, 3, 4, 1]

        # S盒定义
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

        # 用于记录过程
        self.process_log = []

    def log(self, message):
        """记录过程日志"""
        self.process_log.append(message)
        print(message)

    def reset_log(self):
        """重置过程日志"""
        self.process_log = []

    def get_log(self):
        """获取过程日志"""
        return "\n".join(self.process_log)

    def permute(self, data, table):
        """置换函数"""
        result = ''.join([data[table[i] - 1] for i in range(len(table))])
        self.log(f"置换 [{', '.join(map(str, table))}] 应用于 {data} 得到 {result}")
        return result

    def left_shift(self, data, shifts):
        """左移函数"""
        shifted = data[shifts:] + data[:shifts]
        self.log(f"左移 {shifts} 位: {data} → {shifted}")
        return shifted

    def generate_subkeys(self, key):
        """生成子密钥"""
        self.log(f"开始生成子密钥，原始密钥: {key}")

        # P10置换
        p10_key = self.permute(key, self.P10)
        self.log(f"P10置换后: {p10_key}")

        # 分为左右两部分
        left = p10_key[:5]
        right = p10_key[5:]
        self.log(f"分为左右两部分: L={left}, R={right}")

        # 生成K1
        left1 = self.left_shift(left, 1)
        right1 = self.left_shift(right, 1)
        combined1 = left1 + right1
        k1 = self.permute(combined1, self.P8)
        self.log(f"生成K1: {k1}")

        # 生成K2
        left2 = self.left_shift(left1, 2)
        right2 = self.left_shift(right1, 2)
        combined2 = left2 + right2
        k2 = self.permute(combined2, self.P8)
        self.log(f"生成K2: {k2}")

        return k1, k2

    def s_box_lookup(self, input_str, s_box, name):
        """S盒查找"""
        # 计算行和列
        row = int(input_str[0] + input_str[3], 2)
        col = int(input_str[1] + input_str[2], 2)

        # 获取值并转换为2位二进制
        value = s_box[row][col]
        binary = bin(value)[2:].zfill(2)

        self.log(f"{name}盒查找: 输入={input_str}, 行={row}, 列={col}, 值={value}, 二进制={binary}")
        return binary

    def f_function(self, data, subkey):
        """F函数"""
        self.log(f"F函数: 数据={data}, 子密钥={subkey}")

        # 扩展置换
        expanded = self.permute(data, self.EP)
        self.log(f"扩展置换后: {expanded}")

        # 与子密钥异或
        xor_result = ''.join(['1' if a != b else '0' for a, b in zip(expanded, subkey)])
        self.log(f"与子密钥异或: {xor_result}")

        # 分为S1和S2的输入
        s1_input = xor_result[:4]
        s2_input = xor_result[4:]
        self.log(f"S盒输入: S1={s1_input}, S2={s2_input}")

        # S盒代换
        s1_output = self.s_box_lookup(s1_input, self.S1, 'S1')
        s2_output = self.s_box_lookup(s2_input, self.S2, 'S2')
        self.log(f"S盒输出: S1={s1_output}, S2={s2_output}")

        # 合并S盒输出
        combined = s1_output + s2_output
        self.log(f"合并S盒输出: {combined}")

        # P4置换
        p4_result = self.permute(combined, self.P4)
        self.log(f"P4置换后: {p4_result}")

        return p4_result

    def encrypt(self, plaintext, key):
        """加密函数"""
        self.reset_log()
        self.log(f"开始加密: 明文={plaintext}, 密钥={key}")

        # 生成子密钥
        k1, k2 = self.generate_subkeys(key)

        # 初始置换IP
        ip_result = self.permute(plaintext, self.IP)
        self.log(f"初始置换IP后: {ip_result}")

        # 分为左右两部分
        left, right = ip_result[:4], ip_result[4:]
        self.log(f"分为左右两部分: L0={left}, R0={right}")

        # 第1轮加密
        self.log('----- 第1轮加密 -----')
        f1 = self.f_function(right, k1)
        new_left1 = ''.join(['1' if a != b else '0' for a, b in zip(left, f1)])
        new_right1 = right
        self.log(f"第1轮结果: L1={new_left1}, R1={new_right1}")

        # 交换
        swapped_left, swapped_right = new_right1, new_left1
        self.log(f"交换后: L'={swapped_left}, R'={swapped_right}")

        # 第2轮加密
        self.log('----- 第2轮加密 -----')
        f2 = self.f_function(swapped_right, k2)
        new_left2 = ''.join(['1' if a != b else '0' for a, b in zip(swapped_left, f2)])
        new_right2 = swapped_right
        self.log(f"第2轮结果: L2={new_left2}, R2={new_right2}")

        # 合并
        pre_output = new_left2 + new_right2
        self.log(f"合并结果: {pre_output}")

        # 逆初始置换
        ciphertext = self.permute(pre_output, self.IP_INV)
        self.log(f"逆初始置换IP^-1后: {ciphertext}")
        self.log(f"加密完成: 密文={ciphertext}")

        return ciphertext

    def decrypt(self, ciphertext, key):
        """解密函数"""
        self.reset_log()
        self.log(f"开始解密: 密文={ciphertext}, 密钥={key}")

        # 生成子密钥（解密使用相反顺序的子密钥）
        k1, k2 = self.generate_subkeys(key)

        # 初始置换IP
        ip_result = self.permute(ciphertext, self.IP)
        self.log(f"初始置换IP后: {ip_result}")

        # 分为左右两部分
        left, right = ip_result[:4], ip_result[4:]
        self.log(f"分为左右两部分: L0={left}, R0={right}")

        # 第1轮解密（使用K2）
        self.log('----- 第1轮解密 (使用K2) -----')
        f1 = self.f_function(right, k2)
        new_left1 = ''.join(['1' if a != b else '0' for a, b in zip(left, f1)])
        new_right1 = right
        self.log(f"第1轮结果: L1={new_left1}, R1={new_right1}")

        # 交换
        swapped_left, swapped_right = new_right1, new_left1
        self.log(f"交换后: L'={swapped_left}, R'={swapped_right}")

        # 第2轮解密（使用K1）
        self.log('----- 第2轮解密 (使用K1) -----')
        f2 = self.f_function(swapped_right, k1)
        new_left2 = ''.join(['1' if a != b else '0' for a, b in zip(swapped_left, f2)])
        new_right2 = swapped_right
        self.log(f"第2轮结果: L2={new_left2}, R2={new_right2}")

        # 合并
        pre_output = new_left2 + new_right2
        self.log(f"合并结果: {pre_output}")

        # 逆初始置换
        plaintext = self.permute(pre_output, self.IP_INV)
        self.log(f"逆初始置换IP^-1后: {plaintext}")
        self.log(f"解密完成: 明文={plaintext}")

        return plaintext

