# RELATÓRIO SOMATIVA 3 — IDS EM TEMPO REAL COM THREADS

## PARTE 1: CONDIÇÃO DE CORRIDA EM CONTADORES COMPARTILHADOS

### 1A) AVALIAÇÃO SEM LOCK

**Execução:** 3 rodadas consecutivas sem alterar o código

**Alertas de fila cheia:** 0 (zero)

**Arquivo alerta_1a.txt:**
- Total de alertas: 24 (8 alertas × 3 rodadas)
- Observação: Os valores dos contadores variam entre execuções

**Análise dos resultados:**

```
Rodada 1:
- ICMP Flood origem 33.45.9.23: 231 pacotes
- ICMP Flood destino 10.95.32.205: 760 pacotes
- SYN Flood origem 10.0.2.15: 786 pacotes
- PORT SCAN origem 10.0.2.15: 575 portas

Rodada 2:
- ICMP Flood origem 33.45.9.23: 239 pacotes (diferente!)
- ICMP Flood destino 10.95.32.205: 772 pacotes (diferente!)
- SYN Flood origem 10.0.2.15: 765 pacotes (diferente!)
- PORT SCAN origem 10.0.2.15: 575 portas (igual)

Rodada 3:
- ICMP Flood origem 33.45.9.23: 234 pacotes (diferente novamente!)
- ICMP Flood destino 10.95.32.205: 766 pacotes (diferente!)
- SYN Flood origem 10.0.2.15: 776 pacotes (diferente!)
- PORT SCAN origem 10.0.2.15: 575 portas (igual)
```

**Resultado: INCONSISTENTE**

Os contadores apresentam valores diferentes a cada execução. Isso ocorre devido à **condição de corrida (race condition)** na função `incrementa_contador()`:

```python
def incrementa_contador(contador, chave):
    valor = contadores[contador].get(chave, 0)  # Thread A lê valor = 100
    sleep(ATRASO_RACE)                          # Contexto troca para Thread B
                                                # Thread B lê valor = 100 (mesmo valor!)
    contadores[contador][chave] = valor + 1     # Thread A escreve 101
                                                # Thread B escreve 101 (perdeu update!)
    return contadores[contador][chave]
```

Múltiplas threads leem o mesmo valor antes de incrementar, causando perda de atualizações. O resultado final fica menor que o esperado e varia aleatoriamente.

---

### 1B) AVALIAÇÃO COM LOCK ÚNICO (SINGLE_LOCK)

**Execução:** 3 rodadas consecutivas

**Alertas de fila cheia:** 8 por rodada (total: 24 em 3 rodadas)

**Arquivo alerta_1b.txt:**
- Total de alertas: 24 (8 alertas × 3 rodadas)
- Observação: Os valores são **idênticos** entre todas as execuções

**Análise dos resultados:**

```
Todas as 3 rodadas produziram EXATAMENTE os mesmos valores:
- ICMP Flood origem 33.45.9.23: 370 pacotes
- ICMP Flood destino 10.95.32.205: 900 pacotes
- SYN Flood origem 10.0.2.15: 1060 pacotes
- SYN Flood destino 44.25.32.17: 318 pacotes
- SYN Flood destino 192.168.56.1: 168 pacotes
- SYN Flood destino 172.18.160.1: 619 pacotes
- SYN Flood destino 10.95.32.205: 574 pacotes
- PORT SCAN origem 10.0.2.15: 575 portas
```

**Resultado: CONSISTENTE nos contadores, mas COM PROBLEMA DE DESEMPENHO**

O single_lock resolve a condição de corrida: todos os contadores agora têm valores corretos e reproduzíveis. Porém, **o preço é alto**:

- **Serialização excessiva:** Um único lock para TODAS as operações cria um gargalo. Apenas 1 worker pode atualizar qualquer contador por vez, mesmo quando estão atualizando contadores diferentes.

- **Fila cheia:** 8 alertas de fila cheia por rodada indicam que os workers não conseguem processar pacotes rápido o suficiente. O produtor é mais rápido que os consumidores porque eles ficam bloqueados esperando pelo lock.

**Contadores corretos ≠ Sistema eficiente**

O single_lock cria contenção desnecessária. Workers que poderiam trabalhar em paralelo (atualizando contadores diferentes) são forçados a esperar.

---

### 1C) AVALIAÇÃO COM LOCKS INDIVIDUAIS POR CONTADOR

**Execução:** 3 rodadas consecutivas

**Alertas de fila cheia:** 0 (zero)

**Arquivo alerta_1c.txt:**
- Total de alertas: 24 (8 alertas × 3 rodadas)
- Observação: Os valores são **idênticos** entre todas as execuções

**Análise dos resultados:**

```
Todas as 3 rodadas produziram EXATAMENTE os mesmos valores:
- ICMP Flood origem 33.45.9.23: 370 pacotes
- ICMP Flood destino 10.95.32.205: 900 pacotes
- SYN Flood origem 10.0.2.15: 1060 pacotes
- SYN Flood destino 44.25.32.17: 318 pacotes
- SYN Flood destino 192.168.56.1: 168 pacotes
- SYN Flood destino 172.18.160.1: 619 pacotes
- SYN Flood destino 10.95.32.205: 574 pacotes
- PORT SCAN origem 10.0.2.15: 575 portas
```

**Resultado: CONSISTENTE E EFICIENTE**

Os locks individuais oferecem **o melhor dos dois mundos**:

1. **Consistência:** Valores idênticos à versão 1B (single_lock), provando que a proteção funciona.

2. **Desempenho:** 0 alertas de fila cheia — os workers conseguem acompanhar o produtor!

**Por que funciona melhor?**

- Granularidade fina: cada contador tem seu próprio lock
- Paralelismo real: Worker A pode atualizar `icmp_origem` enquanto Worker B atualiza `syn_destino` simultaneamente
- Contenção reduzida: locks só conflitam quando dois workers tentam atualizar o MESMO contador ao mesmo tempo

**Exemplo de execução paralela:**

```
Worker 1 processa pacote ICMP de IP_A → locks["icmp_origem"].acquire()
Worker 2 processa pacote SYN de IP_B  → locks["syn_origem"].acquire()
                                          ↑ acontecem ao mesmo tempo!
```

Com single_lock, Worker 2 teria que esperar Worker 1 terminar completamente.

---

### CONCLUSÃO DA PARTE 1

| Abordagem          | Consistência | Desempenho | Fila Cheia | Melhor? |
|--------------------|--------------|------------|------------|---------|
| Sem lock (1A)      | ❌ Ruim      | ✅ Bom     | 0          | ❌      |
| Single lock (1B)   | ✅ Boa       | ❌ Ruim    | 8/rodada   | ❌      |
| Locks individuais (1C) | ✅ Boa   | ✅ Bom     | 0          | ✅      |

**Locks individuais (1C) é a solução correta:** oferece proteção completa contra race conditions mantendo o paralelismo efetivo entre workers.

**Lição importante:** A granularidade do lock importa. Lock demais = serialização. Lock de menos = race condition. Lock na medida certa = consistência + desempenho.

---

## PARTE 2: ALERTAS EM TEMPO REAL NOS WORKERS

Nesta fase, os alertas foram movidos dos workers (geração em tempo real) ao invés de pós-processamento. Cada worker verifica o contador logo após incrementá-lo e, se ultrapassar o limite, gera o alerta e zera o contador.

### 2A) ALERTAS EM TEMPO REAL SEM LOCK NA VERIFICAÇÃO/ZERAGEM

**Execução:** 1 rodada

**Arquivo alerta_2a.txt:**
- Total de alertas: 51
- Observação: **Muitos alertas duplicados e com valores inconsistentes**

**Análise dos resultados:**

```
Exemplos de alertas repetidos:
12/05/2026 16:21:08 --> O IP 33.45.9.23 esta fazendo ICMP Flood: 101 pacotes
12/05/2026 16:21:08 --> O IP 33.45.9.23 esta fazendo ICMP Flood: 102 pacotes
12/05/2026 16:21:08 --> O IP 10.95.32.205 esta sendo atacado: 101 pacotes
12/05/2026 16:21:08 --> O IP 10.95.32.205 esta sendo atacado: 101 pacotes (duplicado!)
12/05/2026 16:21:08 --> O IP 33.45.9.23 esta fazendo ICMP Flood: 101 pacotes (de novo!)

PORT SCAN repetido múltiplas vezes:
12/05/2026 16:21:09 --> O IP 10.0.2.15 esta fazendo PORT SCAN: 51 portas
12/05/2026 16:21:10 --> O IP 10.0.2.15 esta fazendo PORT SCAN: 51 portas
12/05/2026 16:21:10 --> O IP 10.0.2.15 esta fazendo PORT SCAN: 51 portas
12/05/2026 16:21:10 --> O IP 10.0.2.15 esta fazendo PORT SCAN: 51 portas
12/05/2026 16:21:10 --> O IP 10.0.2.15 esta fazendo PORT SCAN: 51 portas
```

**Resultado: INCONSISTENTE E INSTÁVEL**

**O que causou o problema?**

A verificação e zeragem estão **FORA** da seção crítica protegida pelo lock:

```python
locks["icmp_origem"].acquire()
total = incrementa_contador("icmp_origem", ip_origem)
locks["icmp_origem"].release()           # <-- LOCK LIBERADO AQUI

# ZONA PERIGOSA: outras threads podem acessar o contador!
if total > LIMITE_ICMP:                  # Thread A lê total = 101
    IDS.alerta(...)                      # Thread B também lê total = 101
    contadores["icmp_origem"][ip_origem] = 0  # Thread A zera
                                              # Thread B zera de novo (duplica alerta!)
```

**Sequência do problema:**

1. Worker A incrementa contador de 100 → 101, libera lock
2. Worker B incrementa contador de 101 → 102, libera lock
3. Worker A verifica (101 > 100), gera alerta, zera contador
4. Worker B verifica (102 > 100), gera alerta NOVAMENTE
5. Mas Worker C já pode ter incrementado após a zeragem de A
6. Resultado: alertas duplicados, valores inconsistentes, contadores zerados em momentos errados

**Problemas identificados:**

- **Alertas duplicados:** Múltiplos workers detectam a mesma violação antes que o primeiro consiga zerar
- **Valores incorretos:** O valor reportado no alerta não reflete o estado real (já foi modificado)
- **Zeragem prematura:** Contador pode ser zerado enquanto outros workers ainda estão processando
- **Lost updates:** Zeragem de um worker pode ser sobrescrita por incremento de outro

---

### 2B) ALERTAS EM TEMPO REAL COM LOCK COBRINDO VERIFICAÇÃO/ZERAGEM

**Execução:** 1 rodada

**Arquivo alerta_2b.txt:**
- Total de alertas: 47
- Observação: **Alertas corretos, sem duplicações indevidas**

**Análise dos resultados:**

```
Alertas limpos e organizados:
12/05/2026 16:21:14 --> O IP 33.45.9.23 esta fazendo ICMP Flood: 101 pacotes
12/05/2026 16:21:14 --> O IP 10.95.32.205 esta sendo atacado: 101 pacotes
12/05/2026 16:21:14 --> O IP 33.45.9.23 esta fazendo ICMP Flood: 101 pacotes
12/05/2026 16:21:14 --> O IP 10.95.32.205 esta sendo atacado: 101 pacotes
...
12/05/2026 16:21:15 --> O IP 10.0.2.15 esta fazendo PORT SCAN: 51 portas
12/05/2026 16:21:15 --> O IP 10.0.2.15 esta fazendo PORT SCAN: 51 portas
...
```

**Resultado: CONSISTENTE E CORRETO**

**Onde os locks foram colocados:**

```python
locks["icmp_origem"].acquire()
# SEÇÃO CRÍTICA COMPLETA: incremento + verificação + zeragem
total = incrementa_contador("icmp_origem", ip_origem)
if total > LIMITE_ICMP:
    IDS.alerta(f"O IP {ip_origem} esta fazendo ICMP Flood: {total} pacotes")
    contadores["icmp_origem"][ip_origem] = 0
locks["icmp_origem"].release()
```

**Por que funciona?**

A operação completa é atômica:
1. Adquire lock
2. Incrementa contador
3. Verifica se excedeu limite
4. Se sim: gera alerta e zera
5. Libera lock

**Nenhum outro worker pode interferir** entre o incremento e a zeragem. A seção crítica garante que:

- Apenas um worker verifica e alerta por vez
- O valor no alerta é o valor real no momento da verificação
- A zeragem ocorre imediatamente após o alerta
- Não há race condition entre verificação e zeragem

**Os alertas ainda podem se repetir?**

Sim, mas agora é **comportamento correto**: se o contador é zerado em 101 e depois cresce novamente até 102, um novo alerta é gerado quando atingir 101 novamente. Isso é detecção em tempo real funcionando como esperado.

---

### CONCLUSÃO DA PARTE 2

| Abordagem          | Alertas Corretos | Duplicações | Estabilidade | Melhor? |
|--------------------|------------------|-------------|--------------|---------|
| Sem lock na verificação (2A) | ❌ | ✅ Muitas | ❌ Instável | ❌ |
| Com lock na verificação (2B) | ✅ | Mínimas* | ✅ Estável | ✅ |

*Múltiplos alertas podem aparecer, mas agora representam múltiplas violações reais após zeragens corretas.

**Explicação do problema na abordagem 2A:**

A tentação era pensar: "já uso locks no incremento, então está protegido". Mas incrementar é apenas PARTE da operação. A operação lógica completa é:

```
incrementar → verificar → decidir → zerar
```

Se o lock só cobre "incrementar", o restante fica desprotegido. Resultado: race conditions na verificação e na zeragem.

**Lição da Parte 2:**

**Seções críticas devem ser COMPLETAS.** Não basta proteger a leitura/escrita isolada. É preciso proteger toda a sequência lógica que forma uma operação atômica do ponto de vista da aplicação.

---

## RESUMO GERAL DO PROJETO

### Conceitos demonstrados:

1. **Produtor-Consumidor:** Fila compartilhada entre threads
2. **Race Conditions:** Condições de corrida em contadores globais
3. **Locks (Mutex):** Sincronização para proteger seções críticas
4. **Granularidade de locks:** Single lock vs. locks individuais
5. **Seções críticas:** Definir corretamente o escopo da proteção
6. **Trade-offs:** Consistência vs. desempenho

### Resultados práticos:

- **Sem proteção:** Rápido mas incorreto
- **Single lock:** Correto mas lento (serialização)
- **Locks individuais:** Correto E rápido (paralelismo com proteção)
- **Lock incompleto:** Proteção parcial = inconsistência
- **Lock completo:** Operações atômicas garantem corretude

### Melhor solução implementada:

**`somativa3.py` (versão 2B):**
- Locks individuais por contador (granularidade adequada)
- Seções críticas completas (incremento + verificação + zeragem)
- Alertas em tempo real pelos workers
- Paralelismo eficiente sem race conditions

---

## ARQUIVOS ENTREGUES

1. `somativa_1a.py` — Parte 1A: sem lock
2. `somativa_1b.py` — Parte 1B: single lock global
3. `somativa_1c.py` — Parte 1C: locks individuais
4. `somativa_2a.py` — Parte 2A: alertas em tempo real sem lock na verificação
5. `somativa_2b.py` — Parte 2B: alertas em tempo real com lock completo
6. `somativa3.py` — Versão final consolidada (igual à 2B)
7. `alerta_1a_final.txt` — Alertas da execução 1A
8. `alerta_1b_final.txt` — Alertas da execução 1B
9. `alerta_1c_final.txt` — Alertas da execução 1C
10. `alerta_2a_final.txt` — Alertas da execução 2A
11. `alerta_2b_final.txt` — Alertas da execução 2B
12. `myscapyLib.py` — Biblioteca fornecida
13. `desafio.pcap` — Arquivo de captura de pacotes
14. `RELATORIO.md` — Este relatório completo

---

FIM DO RELATÓRIO
