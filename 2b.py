# PARTE 2B - Alertas em tempo real nos workers, COM lock cobrindo verificação e zeragem

from threading import Thread, Lock
from queue import Queue, Full
from time import sleep
import myscapyLib as IDS
from datetime import datetime

FIM = object()

ARQUIVO = "desafio.pcap"
N_WORKERS = 4

LIMITE_ICMP = 100
LIMITE_SYN = 100
LIMITE_PORTSCAN = 50
ATRASO_RACE = 0.00001

fila = Queue(maxsize=100)

contadores = {
    "icmp_origem": {},
    "icmp_destino": {},
    "syn_origem": {},
    "syn_destino": {},
    "portas_origem": {},
}

# Locks individuais por contador
locks = {
    "icmp_origem": Lock(),
    "icmp_destino": Lock(),
    "syn_origem": Lock(),
    "syn_destino": Lock(),
    "portas_origem": Lock(),
}


def produtor_temporizado(arquivo, fila, n_workers):
    pacotes = IDS.carregaPacotes(
        arquivo,
        tempo_real=True,
        fator_tempo=1/20,
        pausa_maxima=0.1
    )

    full_queues = 0

    for pacote in pacotes:
        while True:
            try:
                fila.put(pacote, block=False)
                break
            except Full:
                print(f"Fila cheia {full_queues}: workers não acompanharam a taxa de pacotes")
                full_queues += 1
                sleep(0.5)

    for _ in range(n_workers):
        fila.put(FIM)


def incrementa_contador(contador, chave):
    valor = contadores[contador].get(chave, 0)
    sleep(ATRASO_RACE)
    contadores[contador][chave] = valor + 1
    return contadores[contador][chave]


def worker(worker_id, fila):
    while True:
        pacote = fila.get()
        if pacote is FIM:
            print(f"worker {worker_id} encerrando")
            break
        if IDS.TIPO["ip"] not in pacote:
            continue

        ip_origem = str(pacote[IDS.TIPO["ip"]].src)
        ip_destino = str(pacote[IDS.TIPO["ip"]].dst)

        if IDS.TIPO["icmp"] in pacote:
            # Lock cobre incremento + verificação + zeragem (seção crítica completa)
            locks["icmp_origem"].acquire()
            total = incrementa_contador("icmp_origem", ip_origem)
            if total > LIMITE_ICMP:
                IDS.alerta(f"O IP {ip_origem} esta fazendo ICMP Flood: {total} pacotes")
                contadores["icmp_origem"][ip_origem] = 0
            locks["icmp_origem"].release()

            locks["icmp_destino"].acquire()
            total = incrementa_contador("icmp_destino", ip_destino)
            if total > LIMITE_ICMP:
                IDS.alerta(f"O IP {ip_destino} esta sendo atacado por ICMP Flood: {total} pacotes")
                contadores["icmp_destino"][ip_destino] = 0
            locks["icmp_destino"].release()

        if IDS.TIPO["tcp"] in pacote:
            tcp = pacote[IDS.TIPO["tcp"]]
            if str(tcp.flags) == "S":
                locks["syn_origem"].acquire()
                total = incrementa_contador("syn_origem", ip_origem)
                if total > LIMITE_SYN:
                    IDS.alerta(f"O IP {ip_origem} esta fazendo SYN Flood: {total} pacotes")
                    contadores["syn_origem"][ip_origem] = 0
                locks["syn_origem"].release()

                locks["syn_destino"].acquire()
                total = incrementa_contador("syn_destino", ip_destino)
                if total > LIMITE_SYN:
                    IDS.alerta(f"O IP {ip_destino} esta sendo atacado por SYN Flood: {total} pacotes")
                    contadores["syn_destino"][ip_destino] = 0
                locks["syn_destino"].release()

                porta = int(tcp.dport)

                locks["portas_origem"].acquire()
                if ip_origem not in contadores["portas_origem"]:
                    contadores["portas_origem"][ip_origem] = set()
                sleep(0)
                contadores["portas_origem"][ip_origem].add(porta)
                qtd_portas = len(contadores["portas_origem"][ip_origem])
                if qtd_portas > LIMITE_PORTSCAN:
                    IDS.alerta(f"O IP {ip_origem} esta fazendo PORT SCAN: {qtd_portas} portas")
                    contadores["portas_origem"][ip_origem] = set()
                locks["portas_origem"].release()


if __name__ == "__main__":
    t_produtor = Thread(
        target=produtor_temporizado,
        args=(ARQUIVO, fila, N_WORKERS)
    )

    workers = [
        Thread(target=worker, args=(i, fila))
        for i in range(N_WORKERS)
    ]

    t_produtor.start()

    for w in workers:
        w.start()

    t_produtor.join()

    for w in workers:
        w.join()

    # gera_alertas_finais() -- REMOVIDO: alertas gerados pelos workers em tempo real
    print("fim")