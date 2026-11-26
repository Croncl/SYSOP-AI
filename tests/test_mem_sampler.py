"""Amostrador de memória (scripts/mem_sampler.py) contra processos reais desta máquina."""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import mem_sampler as M  # noqa: E402


def test_amostra_processo_e_resume(tmp_path, capsys):
    # o filho só avisa depois de alocar (e tocar) os 30 MiB: sem corrida com a amostragem
    alvo = subprocess.Popen([sys.executable, "-c",
                             "import sys, time; x = bytearray(30 * 2**20); print('pronto', flush=True); time.sleep(10)",
                             "marcador-sysop-teste"], stdout=subprocess.PIPE, text=True)
    try:
        assert alvo.stdout.readline().strip() == "pronto"
        out = tmp_path / "mem.csv"
        assert M.main(["--match", "marcador-sysop-teste", "--interval", "0.2", "--duration", "0.7",
                       "--out", str(out)]) == 0
    finally:
        alvo.kill()
    linhas = out.read_text().splitlines()
    assert linhas[0].split(",") == M.FIELDS and len(linhas) >= 3
    assert any(f",{alvo.pid}," in l for l in linhas[1:])
    M.main(["--summary", str(out)])
    txt = capsys.readouterr().out
    assert "marcador-sysop-teste" in txt and "MemAvailable" in txt
    rss = [int(l.split(",")[3]) for l in linhas[1:] if f",{alvo.pid}," in l]
    assert max(rss) > 30 * 1024                                      # os 30 MiB alocados aparecem no VmRSS


def test_sem_processo_registra_a_maquina():
    rows = M.sample(["nenhum-processo-com-este-nome-xyz"], me=0)
    assert len(rows) == 1 and rows[0]["pid"] == "" and rows[0]["mem_available_kb"] > 0
