# Rodadas na placa (O2: latência e memória)

**Para quem opera a Orange Pi 4 Pro.** Neste roteiro a placa só responde aos casos sintéticos do harness. Não há ataque nem ban de verdade. A rodada leva cerca de 4 h e pode ficar durante a noite. O laboratório de ataques é outro roteiro: [`RUNBOOK_LAB.md`](RUNBOOK_LAB.md).

## O que esta rodada mede

O agente decide os 31 casos sintéticos na condição V2 (validação completa). São 3 repetições, com as sementes 42, 43 e 44:
- com o **Qwen2.5-1,5B**, que é o de produção;
- com o **Qwen2.5-3B**.

Ela mede três coisas:
- **Latência:** por incidente e por chamada, com mediana, IQR e p95, além de prefill e geração em tok/s.
- **Memória do llama-server:** RSS e pico, com o modelo ocioso e durante as decisões.
- **Custo do agente sem LLM:** o planejador `regras`.

A qualidade das decisões (V2, V1, V0) roda no PC, porque não depende do hardware. Latência e memória só valem aqui.

## 1. Atualizar o código (5 min)

```bash
cd /home/projetos/SYSOP-AI
git fetch --all --tags
git checkout artigo-u3-rodadas       # tag criada depois do merge do MR da Unidade III
source venv/bin/activate
pip install -r requirements.txt      # nada novo: a avaliação usa só a biblioteca padrão
```

Confira que o `venv/bin/activate` **não** exporta `SYSOP_DB` nem `SYSOP_APPROVALS_DB`. Essas linhas foram comentadas na seção 14.3 do `IMPLANTACAO.md`.

## 2. Conferir os contêineres

```bash
podman ps -a --format '{{.Names}} {{.Status}}'
```

Devem existir dois contêineres: `llama-plan-15b` (produção, 1,5B, porta 8080, serviço `container-llama-plan-15b.service` do usuário) e `llama-plan` (3B).

Se o do 3B não existir, crie-o com as mesmas opções da produção. Só o modelo muda:

```bash
podman create --name llama-plan --network=host --memory=4g --cap-drop=ALL \
  -v /srv/models:/models:ro ghcr.io/ggml-org/llama.cpp:server \
  -m /models/qwen2.5-3b-instruct-q4_k_m.gguf --host 127.0.0.1 --port 8080 --alias react -np 1 -c 2048 -t 4
```

Se os nomes forem outros, passe-os por variável: `C15=... SVC15=... C3=... bash ab_harness/run_u3_placa.sh`.

## 3. Rodar (≈ 4 h)

```bash
nohup bash ab_harness/run_u3_placa.sh > ab_harness/u3_placa.log 2>&1 &
tail -f ab_harness/u3_placa.log        # Ctrl+C só sai do tail; a rodada continua
```

O script segue esta ordem:
1. Roda `pytest` e o `selftest`. Os dois têm de dar OK.
2. Para o `sysopai-agent.timer`, se estiver ativo.
3. Mede 60 s de memória ociosa.
4. Roda o agente sem LLM.
5. Roda o 1,5B, com o amostrador de memória ligado.
6. Troca a produção pelo 3B e roda o 3B.
7. Gera o relatório e empacota.

Ao sair, mesmo com erro ou Ctrl+C no processo, o `trap` religa o contêiner de produção e o timer.

Se a rodada cair (falta de luz, travamento), rode o mesmo comando de novo: o que já terminou é pulado.

Durante a rodada:
- Não use a placa para outra tarefa pesada, porque a banda de memória é compartilhada e altera a latência.
- A temperatura (92–93 °C) é registrada a cada chamada; se a placa estiver sem ventilação, anote.

## 4. Entregar

No fim, o log mostra `pronto: envie u3-placa-AAAAMMDD-HHMM.tar.gz`. Envie esse arquivo e o `.sha256` dele para o grupo (pasta do Drive ou `scp`).

O pacote traz:
- os `.jsonl` e `.meta.json` de cada rodada (com commit, sha256 do dataset, `/props` do llama-server e sementes);
- `mem-*.csv` e os resumos;
- `ambiente.txt` (CPU, memória, `pip freeze` e **sha256 dos `.gguf`**);
- o relatório `relatorio_u3_placa.md`.

**Pedido extra:** se der, copie também os dois `.gguf` de `/srv/models` para o grupo. Com os mesmos arquivos, as rodadas de qualidade no PC usam exatamente o mesmo modelo. Se não der, o PC baixa do Hugging Face e confere o sha256 com o do `ambiente.txt`.

## Problemas comuns

| Sintoma | O que fazer |
|---|---|
| `llama-server não ficou saudável` | `podman logs llama-plan-15b` (ou `llama-plan`); confira se outro processo ocupa a porta 8080 |
| `recusado: ... já existe` | Não acontece pelo script (ele pula); se rodar o runner à mão, use outro `--label` |
| `SELFTEST COM FALHAS` | Pare e avise o grupo: o código na placa não é o da tag |
| A produção não voltou | `systemctl --user start container-llama-plan-15b.service`, depois `curl -s 127.0.0.1:8080/health` |
