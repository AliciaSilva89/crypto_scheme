import hashlib
import time
import random
from typing import List
from collections import defaultdict

# ============================================================================
# FUNÇÕES PRINCIPAIS DO ESQUEMA CRIPTOGRÁFICO
# ============================================================================

def GEN(seed: str) -> List[int]:
    """
    Gera uma chave binária com comprimento 4 * len(seed)
    Utiliza SHA-256 para pseudo-aleatoriedade criptográfica

    Args:
        seed: String semente para geração da chave

    Returns:
        Lista de bits (0s e 1s) de tamanho 4 * len(seed)
    """
    seed_len = len(seed)
    key_len = 4 * seed_len

    hash_obj = hashlib.sha256(seed.encode())
    hash_bytes = hash_obj.digest()

    key_bits = []
    counter = 0

    while len(key_bits) < key_len:
        if counter > 0:
            hash_obj = hashlib.sha256((seed + str(counter)).encode())
            hash_bytes = hash_obj.digest()

        for byte in hash_bytes:
            for i in range(8):
                if len(key_bits) < key_len:
                    key_bits.append((byte >> (7 - i)) & 1)
        counter += 1

    return key_bits[:key_len]


def ENC(K: List[int], M: List[int]) -> List[int]:
    """
    Criptografa a mensagem M usando a chave K
    Implementa 6 rodadas de XOR com chave e permutação

    Args:
        K: Chave binária (lista de 0s e 1s)
        M: Mensagem binária (mesmo tamanho de K)

    Returns:
        Cifra C (lista binária do mesmo tamanho)
    """
    if len(K) != len(M):
        raise ValueError(f"K e M devem ter o mesmo tamanho: K={len(K)}, M={len(M)}")

    n = len(M)
    C = M.copy()
    rounds = 6

    for r in range(rounds):
        # XOR com chave rotacionada
        shift = (r * 11) % n
        for i in range(n):
            C[i] ^= K[(i + shift) % n]

        # Permutação bijetiva (reversível)
        C_temp = C.copy()
        mult = 3 if n % 3 != 0 else 5
        for i in range(n):
            new_pos = (i * mult + r * 7) % n
            C[new_pos] = C_temp[i]

    return C


def DEC(K: List[int], C: List[int]) -> List[int]:
    """
    Descriptografa a cifra C usando a chave K
    Reverte todas as operações de ENC na ordem inversa

    Args:
        K: Chave binária (lista de 0s e 1s)
        C: Cifra binária (mesmo tamanho de K)

    Returns:
        Mensagem original M (lista binária)
    """
    if len(K) != len(C):
        raise ValueError(f"K e C devem ter o mesmo tamanho: K={len(K)}, C={len(C)}")

    n = len(C)
    M = C.copy()
    rounds = 6

    for r in range(rounds - 1, -1, -1):
        # Reverter permutação
        M_temp = M.copy()
        mult = 3 if n % 3 != 0 else 5
        for i in range(n):
            new_pos = (i * mult + r * 7) % n
            M[i] = M_temp[new_pos]

        # Reverter XOR com chave
        shift = (r * 11) % n
        for i in range(n):
            M[i] ^= K[(i + shift) % n]

    return M


# ============================================================================
# FUNÇÕES DE TESTE E AVALIAÇÃO
# ============================================================================

def test_basic_functionality():
    """Testa se o sistema de criptografia funciona corretamente"""
    print("TESTE BÁSICO DE FUNCIONAMENTO")
    print("-" * 70)

    success_count = 0
    total_tests = 100

    for i in range(total_tests):
        seed = f"test{i:04d}"
        K = GEN(seed)
        M = [random.randint(0, 1) for _ in range(len(K))]
        C = ENC(K, M)
        M_dec = DEC(K, C)

        if M == M_dec:
            success_count += 1
        else:
            print(f"  ✗ Erro no teste {i}")

    print(f"\nResultados: {success_count}/{total_tests} testes bem-sucedidos")

    if success_count == total_tests:
        print("✓ Sistema funcionando PERFEITAMENTE!\n")
        return True
    else:
        print(f"✗ {total_tests - success_count} testes falharam!\n")
        return False


def test_execution_time():
    """1. Teste de Tempo de Execução"""
    print("1. TESTE DE TEMPO DE EXECUÇÃO")
    print("-" * 70)

    seed_sizes = [10, 50, 100, 200, 500]

    print(f"{'Seed':>10} | {'Key (bits)':>12} | {'GEN (ms)':>10} | {'ENC (ms)':>10} | {'DEC (ms)':>10} | {'Total (ms)':>12}")
    print("-" * 90)

    for seed_size in seed_sizes:
        seed = "a" * seed_size
        K = GEN(seed)
        M = [random.randint(0, 1) for _ in range(len(K))]

        # Tempo de GEN (média de 100 execuções)
        start = time.time()
        for _ in range(100):
            _ = GEN(seed)
        time_gen = (time.time() - start) / 100

        # Tempo de ENC
        start = time.time()
        for _ in range(100):
            _ = ENC(K, M)
        time_enc = (time.time() - start) / 100

        # Tempo de DEC
        C = ENC(K, M)
        start = time.time()
        for _ in range(100):
            _ = DEC(K, C)
        time_dec = (time.time() - start) / 100

        total = time_gen + time_enc + time_dec

        print(f"{seed_size:10d} | {len(K):12d} | {time_gen*1000:10.4f} | {time_enc*1000:10.4f} | {time_dec*1000:10.4f} | {total*1000:12.4f}")

    print("\n✓ Complexidade O(n) - Tempo cresce linearmente com o tamanho\n")


def test_equivalent_keys():
    """2. Teste de Chaves Equivalentes"""
    print("2. TESTE DE CHAVES EQUIVALENTES")
    print("-" * 70)

    seed_len = 8
    M_fixed = [random.randint(0, 1) for _ in range(4 * seed_len)]
    num_tests = 2000
    ciphertexts = defaultdict(list)

    print(f"Testando {num_tests} seeds diferentes com mensagem fixa")
    print(f"Tamanho da mensagem: {len(M_fixed)} bits\n")

    for i in range(num_tests):
        seed = f"s{i:07d}"  # Seed de 8 caracteres
        K = GEN(seed)
        C = ENC(K, M_fixed)
        C_str = ''.join(map(str, C))
        ciphertexts[C_str].append(seed)

    # Analisar colisões
    collision_groups = [seeds for seeds in ciphertexts.values() if len(seeds) > 1]
    equivalents = sum(len(seeds) - 1 for seeds in collision_groups)

    print(f"Resultados:")
    print(f"  Chaves testadas: {num_tests}")
    print(f"  Cifras únicas: {len(ciphertexts)}")
    print(f"  Chaves equivalentes: {equivalents} ({equivalents/num_tests*100:.3f}%)")

    if equivalents == 0:
        print("\n  ✓ EXCELENTE! Nenhuma chave equivalente encontrada")
    elif equivalents < 5:
        print(f"\n  ✓ MUITO BOM! Apenas {equivalents} colisões em {num_tests} testes")
    elif equivalents < 20:
        print(f"\n  ✓ BOM! Poucas colisões detectadas ({len(collision_groups)} grupos)")
    else:
        print(f"\n  ⚠ Atenção: {len(collision_groups)} grupos com colisões")
        for i, seeds in enumerate(collision_groups[:3]):
            print(f"    Grupo {i+1}: {seeds[:2]}...")

    print()


def test_diffusion():
    """3. Teste de Difusão (Avalanche Effect)"""
    print("3. TESTE DE DIFUSÃO (Avalanche Effect)")
    print("-" * 70)

    # Testar com múltiplos tamanhos
    test_seeds = ["diff10", "diffusion50char" + "x"*35, "d"*100]

    for seed in test_seeds:
        K = GEN(seed)
        n = len(K)
        M_original = [random.randint(0, 1) for _ in range(n)]
        C_original = ENC(K, M_original)

        diffusion_results = []

        for bit_pos in range(n):
            M_modified = M_original.copy()
            M_modified[bit_pos] ^= 1  # Alterar 1 bit
            C_modified = ENC(K, M_modified)
            bits_changed = sum(c1 != c2 for c1, c2 in zip(C_original, C_modified))
            diffusion_results.append(bits_changed)

        avg = sum(diffusion_results) / len(diffusion_results)
        percentage = avg / n * 100

        print(f"\nTamanho: {n} bits")
        print(f"  Média de bits alterados: {avg:.2f} / {n} ({percentage:.1f}%)")
        print(f"  Mínimo: {min(diffusion_results)} ({min(diffusion_results)/n*100:.1f}%)")
        print(f"  Máximo: {max(diffusion_results)} ({max(diffusion_results)/n*100:.1f}%)")
        print(f"  Ideal: ~{n/2:.0f} bits (50%)")

        if percentage >= 45:
            print(f"  ✓ EXCELENTE difusão! (≥45%)")
        elif percentage >= 35:
            print(f"  ✓ BOA difusão (≥35%)")
        elif percentage >= 25:
            print(f"  ✓ Difusão aceitável (≥25%)")
        else:
            print(f"  ⚠ Difusão baixa (<25%)")

    print()


def test_confusion():
    """4. Teste de Confusão (Key Sensitivity)"""
    print("4. TESTE DE CONFUSÃO (Key Sensitivity)")
    print("-" * 70)

    test_seeds = ["confuse10", "confusion_test_50" + "x"*33]

    for seed_original in test_seeds:
        K_original = GEN(seed_original)
        n = len(K_original)
        M_fixed = [random.randint(0, 1) for _ in range(n)]
        C_original = ENC(K_original, M_fixed)

        confusion_results = []

        for pos in range(len(seed_original)):
            seed_mod = list(seed_original)
            seed_mod[pos] = chr((ord(seed_mod[pos]) + 1 - 32) % 95 + 32)
            K_mod = GEN(''.join(seed_mod))
            C_mod = ENC(K_mod, M_fixed)
            bits_changed = sum(c1 != c2 for c1, c2 in zip(C_original, C_mod))
            confusion_results.append(bits_changed)

        avg = sum(confusion_results) / len(confusion_results)
        percentage = avg / n * 100

        print(f"\nSeed: '{seed_original[:20]}...' ({len(seed_original)} chars)")
        print(f"Tamanho da chave: {n} bits")
        print(f"  Média de bits alterados: {avg:.2f} / {n} ({percentage:.1f}%)")
        print(f"  Mínimo: {min(confusion_results)} ({min(confusion_results)/n*100:.1f}%)")
        print(f"  Máximo: {max(confusion_results)} ({max(confusion_results)/n*100:.1f}%)")
        print(f"  Ideal: ~{n/2:.0f} bits (50%)")

        if percentage >= 45:
            print(f"  ✓ EXCELENTE confusão! (≥45%)")
        elif percentage >= 35:
            print(f"  ✓ BOA confusão (≥35%)")
        elif percentage >= 25:
            print(f"  ✓ Confusão aceitável (≥25%)")
        else:
            print(f"  ⚠ Confusão baixa (<25%)")

    print()


# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("ESQUEMA CRIPTOGRÁFICO SIMPLIFICADO - AVALIAÇÃO COMPLETA")
    print("=" * 70)
    print()

    # Executar teste básico primeiro
    if not test_basic_functionality():
        print("\n⚠ ATENÇÃO: Sistema não passou no teste básico!")
        print("Verifique a implementação antes de continuar.\n")
        exit(1)

    # Executar todos os testes de avaliação
    test_execution_time()
    test_equivalent_keys()
    test_diffusion()
    test_confusion()

    print("=" * 70)
    print("AVALIAÇÃO CONCLUÍDA COM SUCESSO!")
    print("=" * 70)
