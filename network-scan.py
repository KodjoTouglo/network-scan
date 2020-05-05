import scapy.all as scapy


def scanIp(ip):
    #creation d'une requete ARP
    requete_arp = scapy.ARP(pdst = ip)

    #adresse mac de diffusion
    diffusion = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    #combinaison de la trame ether à la requete ARP pour envoi
    requete_arp_diffusion = diffusion/requete_arp

    #scapy.srp pour envoi du paquet dans la couche2 
    #tiemout spécifie le temps qu'il faut pour avoir le retour
    answered_list = scapy.srp(requete_arp_diffusion, timeout=1)[0] 

    #declaration d'une list pour clients
    clients_list = []

    for elements in answered_list:
        client_dict = {"ip":elements[1].psrc,"mac":elements[1].hwsrc}

        #recevoir les IP et MAC dans un dictionnaire
        clients_list.append(client_dict)
    return clients_list



def resultat(list_result):
    print("================================================================================")
    print("Adresse IP\t\t\tAdresse MAC")
    print("=================================================================================")
    for client in list_result:
        print(client['ip'],"\t\t",client['mac'])


print("=================================================================================")
print("Ce programme permet d'afficher tous les périphériques connectés à un réseau donné")
print("=================================================================================")
print("Donner une adresse IP Ex:192.168.1.27 ou une plage d'adresse IP Ex:192.168.74.1/24 ")
print("=================================================================================")
print()
ip=input("=> ")
affichage = scanIp(f"{ip}")
resultat(affichage)
