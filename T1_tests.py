# T1_tests.py
# 交互式测试脚本，便于课堂演示逐项运行第1~5关
# 在命令行下运行： python3 T1_tests.py
# 根据提示选择要运行的测试项，脚本会打印结果与耗时，并可要求保存到文件。

from T1_SDES import SDES
import time
import csv
from typing import List, Tuple


def menu():
    print("====== S-DES 交互式测试（课堂演示） ======")
    print("1) 第1关：基本加/解密示例")
    print("2) 第2关：交叉测试说明与示例")
    print("3) 第3关：ASCII 模式演示")
    print("4) 第4关：暴力破解演示（单对 / 多对）")
    print("5) 第5关：碰撞分析（统计并导出 CSV）")
    print("6) 退出")
    choice = input("请选择操作 (1-6): ").strip()
    return choice


def basic_demo(sdes: SDES):
    print("\n-- 第1关：基本加/解密 --")
    plaintext = input("请输入 8-bit 明文（默认 10110101）: ").strip() or "10110101"
    key = input("请输入 10-bit 密钥（默认 1010000010）: ").strip() or "1010000010"
    t0 = time.perf_counter()
    cipher = sdes.encrypt(plaintext, key)
    t1 = time.perf_counter()
    print(f"加密耗时: {t1 - t0:.6f} 秒, 密文 = {cipher}")
    print("加密过程日志:")
    print(sdes.get_log())
    t2 = time.perf_counter()
    recovered = sdes.decrypt(cipher, key)
    t3 = time.perf_counter()
    print(f"解密耗时: {t3 - t2:.6f} 秒, 解密结果 = {recovered}")
    print("解密过程日志:")
    print(sdes.get_log())
    print(f"明文与解密结果一致？ {recovered == plaintext}")


def cross_demo(sdes: SDES):
    print("\n-- 第2关：交叉测试说明与示例 --")
    print("交叉测试通常在两台不同设备上运行：A、B 使用相同算法和密钥 K。")
    plaintext = input("示例明文（8-bit，默认 10110101）: ").strip() or "10110101"
    key = input("示例密钥（10-bit，默认 1010000010）: ").strip() or "1010000010"
    c = sdes.encrypt(plaintext, key)
    print(f"A 端加密得到 C = {c}")
    recovered = sdes.decrypt(c, key)
    print(f"B 端解密得到 P = {recovered}")
    print(f"是否一致: {recovered == plaintext}")
    print("课堂演示提示：将生成的 C 与另一台运行相同代码的机器交叉验证。" )


def ascii_demo(sdes: SDES):
    print("\n-- 第3关：ASCII 模式演示 --")
    text = input("请输入 ASCII 明文（默认 'Hello!'）: ").strip() or "Hello!"
    key = input("请输入 10-bit 密钥（默认 1010000010）: ").strip() or "1010000010"
    t0 = time.perf_counter()
    blocks = sdes.encrypt_ascii_to_bitblocks(text, key)
    t1 = time.perf_counter()
    print(f"加密耗时: {t1 - t0:.6f} 秒")
    print("每字节对应的 8-bit 密文块（逗号分隔）:")
    print(", ".join(blocks))
    recovered = sdes.decrypt_bitblocks_to_ascii(blocks, key)
    print("解密还原 ASCII:", recovered)
    print("与原始一致？", recovered == text)


def bruteforce_demo(sdes: SDES):
    print("\n-- 第4关：暴力破解演示 --")
    num_pairs = int(input("请输入已知明密文对数目 (1 或 >=2 推荐，输入1表示单对): ").strip() or "1")
    pairs: List[Tuple[str, str]] = []
    for i in range(num_pairs):
        p = input(f"第{i+1}对 明文 (8-bit)，默认 10110101: ").strip() or "10110101"
        c = input(f"第{i+1}对 密文 (8-bit)，若留空程序会用默认密钥生成: ").strip()
        if not c:
            # 若未提供密文则生成（提示）
            key_for_gen = input("为生成示例密文请输入密钥（10-bit），默认 1010000010: ").strip() or "1010000010"
            c = sdes.encrypt(p, key_for_gen)
            print(f"生成的密文: {c} （使用密钥 {key_for_gen}）")
        pairs.append((p, c))

    use_threads = input("是否启用多线程加速? (y/n, 默认 y): ").strip().lower() != 'n'
    max_workers = int(input("并行线程数 (默认 8): ").strip() or "8")

    print("开始暴力破解（遍历 1024 个密钥）...")
    t0 = time.perf_counter()
    if len(pairs) == 1:
        matches, elapsed = sdes.brute_force_search_single_pair(pairs[0][0], pairs[0][1], use_threads=use_threads,
                                                               max_workers=max_workers)
    else:
        matches, elapsed = sdes.brute_force_search_multiple_pairs(pairs, use_threads=use_threads,
                                                                  max_workers=max_workers)
    t1 = time.perf_counter()
    print(f"暴力破解完成（脚本计时 {t1 - t0:.6f} 秒；内部返回耗时 {elapsed:.6f} 秒）")
    print(f"匹配密钥数: {len(matches)}")
    if matches:
        print("前 20 个候选密钥（若更多则只显示 20）:")
        for k in matches[:20]:
            print(k)
        save = input("是否导出候选密钥到 CSV 文件? (y/n): ").strip().lower() == 'y'
        if save:
            path = input("输入保存文件名（默认 bruteforce_candidates.csv）: ").strip() or "bruteforce_candidates.csv"
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['candidate_key_10bit'])
                for k in matches:
                    writer.writerow([k])
            print(f"已保存到 {path}")


def collision_demo(sdes: SDES):
    print("\n-- 第5关：碰撞分析 --")
    p = input("请输入要分析的明文 (8-bit，默认 10110101): ").strip() or "10110101"
    t0 = time.perf_counter()
    collisions = sdes.analyze_collision_for_plaintext(p)
    t1 = time.perf_counter()
    print(f"分析完成，耗时 {t1 - t0:.6f} 秒。找到 {len(collisions)} 个密文由多个密钥产生。")
    # 打印部分结果
    printed = 0
    for c, keys in collisions.items():
        print(f"{c} -> {len(keys)} keys, 示例 keys: {keys[:10]}")
        printed += 1
        if printed >= 10:
            break
    save = input("是否导出完整碰撞结果为 CSV? (y/n): ").strip().lower() == 'y'
    if save:
        path = input("输入保存文件名（默认 collision_results.csv）: ").strip() or "collision_results.csv"
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['ciphertext_8bit', 'num_keys', 'example_keys'])
            for c, keys in collisions.items():
                w.writerow([c, len(keys), ";".join(keys[:20])])
        print(f"已保存到 {path}")


def main():
    sdes = SDES()
    while True:
        choice = menu()
        if choice == '1':
            basic_demo(sdes)
        elif choice == '2':
            cross_demo(sdes)
        elif choice == '3':
            ascii_demo(sdes)
        elif choice == '4':
            bruteforce_demo(sdes)
        elif choice == '5':
            collision_demo(sdes)
        elif choice == '6':
            print("退出。")
            break
        else:
            print("无效选择，请重试。")
        input("\n按回车返回主菜单...")


if __name__ == "__main__":
    main()







# # T1_tests.py
# # 命令行测试脚本，演示并记录 5 个关卡的测试结果
# # 运行方式: python3 T1_tests.py
# #
# # 输出：会在当前目录生成 tests_output.txt（包含日志与结果摘要）

# import os
# from T1_SDES import SDES
# import time
# from typing import List, Tuple

# OUTPUT_FILE = "tests_output.txt"


# def write_output(text: str, mode='a'):
#     with open(OUTPUT_FILE, mode, encoding='utf-8') as f:
#         f.write(text + '\n')


# def test_basic_encrypt_decrypt(sdes: SDES):
#     write_output("==== 第1关：基本测试 ====", mode='w')
#     plaintext = "10110101"
#     key = "1010000010"
#     write_output(f"测试明文(8-bit) = {plaintext}, 密钥(10-bit) = {key}")

#     c = sdes.encrypt(plaintext, key)
#     write_output("加密过程日志:\n" + sdes.get_log())
#     write_output(f"生成密文 = {c}")

#     p = sdes.decrypt(c, key)
#     write_output("解密过程日志:\n" + sdes.get_log())
#     write_output(f"解密得到明文 = {p}")
#     write_output(f"明文是否与原始一致: {p == plaintext}")
#     write_output("")


# def test_cross_implementation_check(sdes: SDES):
#     write_output("==== 第2关：交叉测试（说明/说明性） ====")
#     # 交叉测试在课堂上两台不同程序间进行，这里我们说明如何操作并给出示例：
#     write_output("说明: 在 A、B 两组计算机上使用相同明文和密钥进行加密，验证密文相同；"
#                  "或在 B 端对 A 端加密得到的密文进行解密能还原明文。")
#     write_output("示例（单实例）: 使用本地实现作为 A 端的参考：")
#     plaintext = "10110101"
#     key = "1010000010"
#     ciphertext = sdes.encrypt(plaintext, key)
#     write_output(f"A 端加密得到 C = {ciphertext}")
#     write_output("在 B 端使用相同 K 解密 C，应该得到相同明文 (见下):")
#     recovered = sdes.decrypt(ciphertext, key)
#     write_output(f"B 端解密得到 P = {recovered}")
#     write_output(f"是否一致: {recovered == plaintext}")
#     write_output("")


# def test_ascii_extension(sdes: SDES):
#     write_output("==== 第3关：ASCII 扩展 ====")
#     plaintext = "Hello!"
#     key = "1010000010"
#     write_output(f"ASCII 明文 = {plaintext}")
#     ciphertext_blocks = sdes.encrypt_ascii_to_bitblocks(plaintext, key)
#     write_output("每字节加密得到的 8-bit 列表:")
#     write_output(", ".join(ciphertext_blocks))
#     # 解密回去
#     recovered = sdes.decrypt_bitblocks_to_ascii(ciphertext_blocks, key)
#     write_output(f"解密回 ASCII = {recovered}")
#     write_output(f"是否与原文一致: {recovered == plaintext}")
#     write_output("注: 密文也可按字节直接转换为字符（可能为不可打印的乱码），此处以 8-bit 表示。")
#     write_output("")


# def test_bruteforce(sdes: SDES):
#     write_output("==== 第4关：暴力破解 ====")
#     # 先设置一组已知明密文对（单对）
#     plaintext = "10110101"
#     key = "1010000010"
#     ciphertext = sdes.encrypt(plaintext, key)
#     write_output(f"已知 (P,C) = ({plaintext}, {ciphertext}) （实际 K 隐藏）")

#     # 单对暴力破解（多线程）
#     write_output("开始暴力破解（单对，使用多线程） ...")
#     matches, elapsed = sdes.brute_force_search_single_pair(plaintext, ciphertext, use_threads=True, max_workers=8)
#     write_output(f"暴力破解完成，耗时 {elapsed:.6f} 秒，找到 {len(matches)} 个候选密钥")
#     write_output("候选密钥列表:")
#     write_output(", ".join(matches))
#     write_output("")

#     # 多对示例（可提高唯一性）
#     write_output("多对暴力破解示例（使用两对）:")
#     # 生成第二对（使用同一 K）
#     p2 = "01010101"
#     c2 = sdes.encrypt(p2, key)
#     write_output(f"已知 (P1,C1)=({plaintext},{ciphertext}), (P2,C2)=({p2},{c2})")
#     pairs = [(plaintext, ciphertext), (p2, c2)]
#     matches2, elapsed2 = sdes.brute_force_search_multiple_pairs(pairs, use_threads=True, max_workers=8)
#     write_output(f"多对暴力破解完成，耗时 {elapsed2:.6f} 秒，候选密钥数={len(matches2)}")
#     write_output("候选密钥列表:")
#     write_output(", ".join(matches2))
#     write_output("")


# def test_collision_analysis(sdes: SDES):
#     write_output("==== 第5关：封闭测试（密钥碰撞分析） ====")
#     plaintext = "10110101"
#     write_output(f"分析明文 = {plaintext} 在所有 1024 个密钥下的密文映射情况...")
#     collisions = sdes.analyze_collision_for_plaintext(plaintext)
#     write_output(f"找到 {len(collisions)} 个密文由多个不同密钥产生（即存在碰撞）")
#     # 展示若干碰撞样例（只展示前 5 个以防文件过大）
#     count = 0
#     for c, keys in collisions.items():
#         write_output(f"密文 {c} 由 {len(keys)} 个密钥产生（示例密钥前 10 个）: {keys[:10]}")
#         count += 1
#         if count >= 5:
#             break
#     write_output("注: 可据此进一步分析是否某明文会被显著多组密钥映射到相同密文（实验/统计题）")
#     write_output("")


# def main():
#     sdes = SDES()
#     if os.path.exists(OUTPUT_FILE):
#         os.remove(OUTPUT_FILE)

#     test_basic_encrypt_decrypt(sdes)
#     test_cross_implementation_check(sdes)
#     test_ascii_extension(sdes)
#     test_bruteforce(sdes)
#     test_collision_analysis(sdes)

#     print(f"所有测试完成。输出文件: {OUTPUT_FILE}")
#     print("请打开该文件以查看详细测试日志与结果。")


# if __name__ == "__main__":
#     main()
