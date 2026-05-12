# https://scapy.readthedocs.io/en/latest/
# https://scapy.readthedocs.io/en/latest/api/scapy.packet.html

# sudo apt-get install python3-scapy
# python -m pip install scapy

from datetime import datetime
import time

import scapy.all as scapy
from scapy.all import ARP, ICMP, IP, TCP, UDP, PcapReader, rdpcap, sniff, wrpcap

#-----------------------------------------------------------------------------------------------------
# Declaracao de protocolos
TIPO = {
    'arp': ARP,
    'ip': IP,
    'icmp': ICMP,
    'tcp': TCP,
    'udp': UDP,
}

#-----------------------------------sudo apt-get update && sudo apt-get install libpcap-dev-------------------------------------------------------------------
# Salva ALERTA NO LOG
def alerta(msg):
    with open('alerta2b.txt', 'a') as log:
        now = datetime.now()
        log.write(now.strftime("%d/%m/%Y %H:%M:%S") + ' --> ' + msg + '\n')

#------------------------------------------------------------------------------------------------------
# Gerador de pacotes lidos incrementalmente de um arquivo PCAP.
# -- Nao carrega o arquivo inteiro na memoria.
# -- Se respeita_tempo=True, reproduz os intervalos originais entre pacotes.
# -- fator_tempo=1.0 preserva o tempo real; 0.5 fica 2x mais rapido; 0 remove espera.
# -- pausa_maxima limita intervalos longos entre pacotes.
def geraPacotes(arquivo, *, respeita_tempo=True, fator_tempo=1.0, pausa_maxima=None, limite=0):
    leitor = None
    anterior = None
    lidos = 0

    try:
        leitor = PcapReader(arquivo)

        for pacote in leitor:
            if limite > 0 and lidos >= limite:
                break

            if respeita_tempo and anterior is not None:
                intervalo = float(pacote.time) - anterior
                if intervalo > 0:
                    if pausa_maxima is not None:
                        intervalo = min(intervalo, pausa_maxima)
                    time.sleep(intervalo * fator_tempo)

            anterior = float(pacote.time)
            lidos += 1
            yield pacote

    except Exception as e:
        print('ERRO: ', e)

    finally:
        if leitor is not None:
            leitor.close()

#------------------------------------------------------------------------------------------------------
# 1) carrega ou captura pacotes
# -- count = numero de pacotes para sniffar
# -- Use count > 0 para capturar pacotes da rede, mas precisa de permissao de administrador.
# -- Use tempo_real=True para ler PCAP de forma incremental, pacote por pacote, com yield.
def carregaPacotes(
    arquivo,
    count=0,
    *,
    tempo_real=False,
    respeita_tempo=True,
    fator_tempo=1.0,
    pausa_maxima=None,
    limite=0,
):
    if tempo_real:
        return geraPacotes(
            arquivo,
            respeita_tempo=respeita_tempo,
            fator_tempo=fator_tempo,
            pausa_maxima=pausa_maxima,
            limite=limite,
        )

    try:
        if count > 0:
            pacotes = sniff(count=count)
            wrpcap(arquivo, pacotes)
        else:
            pacotes = rdpcap(arquivo)
    except Exception as e:
        print('ERRO: ', e)
        pacotes = None

    return pacotes

#------------------------------------------------------------------------------------------------------
def _mostraPacote(pacote, sumario=True):
    if not sumario:
        pacote.show()
    else:
        print(pacote.summary())

#------------------------------------------------------------------------------------------------------
# 2) Mostra captura
# -- Por default, mostra apenas o sumario.
# -- Por default, usa begin=0 e count=100.
# -- Aceita listas de pacotes e tambem geradores produzidos por carregaPacotes(..., tempo_real=True).
def mostraPacotes(pacotes, **kwargs):
    if pacotes is None:
        print('Este arquivo esta vazio')
        return

    ini = kwargs.get('begin', 0)
    qtd = kwargs.get('count', 100)
    fim = ini + qtd
    sumario = kwargs.get('summary', True)

    materializado = hasattr(pacotes, '__len__') and hasattr(pacotes, '__getitem__')

    if materializado:
        if len(pacotes) == 0:
            print('Este arquivo esta vazio')
            return

        print('Pacotes no arquivo: ', len(pacotes))
        p0 = datetime.fromtimestamp(int(pacotes[0].time))
        pn = datetime.fromtimestamp(int(pacotes[-1].time))
        print(f'Captura de: {p0} ate {pn}')
        print(f'Duracao em segundos: {(pn - p0).total_seconds()}')

        for pacote in pacotes[ini:fim]:
            _mostraPacote(pacote, sumario)

        return

    mostrados = 0
    for i, pacote in enumerate(pacotes):
        if i < ini:
            continue
        if mostrados >= qtd:
            break
        _mostraPacote(pacote, sumario)
        mostrados += 1

    if mostrados == 0:
        print('Nenhum pacote para mostrar')

#------------------------------------------------------------------------------------------------------
# 3) Conta pacotes por origem
# -- Para detectar flood, o ideal e contar pacotes que chegaram em um intervalo curto.
def contaIPOrigem(packets):
    origens = {}

    for p in packets:
        if IP in p:
            ip = str(p[IP].src)
            origens[ip] = origens.get(ip, 0) + 1

    return origens

#------------------------------------------------------------------------------------------------------
# 4) Conta pacotes por destino
# -- Para detectar flood, o ideal e contar pacotes que chegaram em um intervalo curto.
def contaIPDestino(packets):
    destinos = {}

    for p in packets:
        if IP in p:
            ip = str(p[IP].dst)
            destinos[ip] = destinos.get(ip, 0) + 1

    return destinos

#------------------------------------------------------------------------------------------------------
# 5) Filtra os pacotes por tipo: ARP, IP, UDP, TCP ou ICMP
# -- lazy=False mantem o comportamento antigo: retorna lista.
# -- lazy=True retorna gerador, adequado para leitura incremental.
def filtraTipo(packets, tipo, *, lazy=False):
    def gerador():
        for pkt in packets:
            if tipo in pkt:
                yield pkt

    return gerador() if lazy else list(gerador())

#------------------------------------------------------------------------------------------------------
# 6) Filtra pacotes TCP por FLAG
# -- flags sao passados como string: 'S', 'SA', 'F', etc.
# -- lazy=False mantem o comportamento antigo: retorna lista.
# -- lazy=True retorna gerador, adequado para leitura incremental.
def filtraTCP(packets, flags, *, lazy=False):
    def gerador():
        for p in packets:
            if TCP in p and str(p[TCP].flags) == flags:
                yield p

    return gerador() if lazy else list(gerador())

#-------------------------------------------------------------------------
# DEMONSTRACAO DAS FUNCOES DA BIBLIOTECA

if __name__ == '__main__':

    # Modo antigo: carrega o PCAP inteiro.
    pacotes = carregaPacotes('desafio.pcap')
    mostraPacotes(pacotes, count=10)

    # Modo incremental: nao carrega tudo antes de iniciar o processamento.
    # pacotes = carregaPacotes('desafio.pcap', tempo_real=True, fator_tempo=1.0)
    # mostraPacotes(pacotes, count=10)

    # Filtro incremental:
    # pacotes = carregaPacotes('desafio.pcap', tempo_real=True, fator_tempo=0)
    # syns = filtraTCP(pacotes, 'S', lazy=True)
    # mostraPacotes(syns, count=10)
