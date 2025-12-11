#include "Logic_Server.h"
#include "Commands_Processing.h"
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std;

Server::Server(int port, int min_threaduri, int max_threaduri) {
  this->port = port;
  this->min_threaduri = min_threaduri;
  this->max_threaduri = max_threaduri;

  // Initializam baza de date (cale relativa catre folderul SQL.lite_db)
  this->baza_date = new ManagerBazaDate("../SQL.lite_db/nms_romania.db");

  InitializeazaServer();
  InitializeazaPoolThreaduri();
}

void Server::InitializeazaServer() {
  // Pasul 1: Creaza socket-ul de ascultare
  this->socket_server = socket(AF_INET, SOCK_STREAM, 0);

  if (this->socket_server < 0) {
    cerr << "Eroare la crearea socket-ului!" << endl;
    exit(1);
  }

  // Pasul 2: Completeaza structura cu adresa si portul
  struct sockaddr_in adresa;
  adresa.sin_family = AF_INET;
  adresa.sin_addr.s_addr = INADDR_ANY;
  adresa.sin_port = htons(this->port);

  // Pasul 3: Leaga socket-ul de port
  if (bind(this->socket_server, (struct sockaddr *)&adresa, sizeof(adresa)) <
      0) {
    cerr << "Eroare la asignarea portului " << this->port << endl;
    exit(1);
  }

  // Pasul 4: Incepe ascultarea
  if (listen(this->socket_server, 100) < 0) {
    cerr << "Eroare la pornirea ascultarii!" << endl;
    exit(1);
  }

  cout << "✓ Serverul asculta pe portul " << this->port << endl;
}

void Server::Ruleaza() {
  cout << "Serverul ruleaza, asteapta conexiuni..." << endl;

  while (true) {
    struct sockaddr_in adresa_client;
    socklen_t lungime_client = sizeof(adresa_client);

    // Accepta client nou
    int socket_client =
        accept(this->socket_server, (struct sockaddr *)&adresa_client,
               &lungime_client);

    if (socket_client < 0) {
      cerr << "Eroare la acceptarea clientului" << endl;
      continue;
    }

    cout << "✓ Client nou conectat! Socket: " << socket_client << endl;

    // Adauga sarcina in coada
    {
      lock_guard<mutex> blocare(mutex_coada);
      coada_sarcini.push(
          [this, socket_client]() { ProcseazaClient(socket_client); });
    }

    // Trezeste un thread sa proceseze sarcina
    conditie_trezire.notify_one();

    // Verifica daca trebuie sa cream mai multe threaduri
    {
      lock_guard<mutex> blocare(mutex_coada);
      int marime_coada = coada_sarcini.size();

      // Daca coada are multe sarcini (peste 80% din numarul de threaduri)
      if (marime_coada > (threaduri_curente * 4 / 5) &&
          threaduri_curente < max_threaduri) {
        int threaduri_de_adaugat =
            min(threaduri_curente, max_threaduri - threaduri_curente);

        cout << "🔥 Coada incarcat! Adaug " << threaduri_de_adaugat
             << " threaduri..." << endl;

        AdaugaThreaduri(threaduri_de_adaugat);
      }
    }
  }
}

void Server::InitializeazaPoolThreaduri() {
  this->threaduri_curente = this->min_threaduri;

  // Creeaza threadurile initiale
  for (int i = 0; i < this->threaduri_curente; i++) {
    threaduri_lucru.emplace_back(&Server::FunctieThreadLucrator, this);
  }

  cout << "✓ Pool de threaduri initializat cu " << threaduri_curente
       << " threaduri" << endl;
}

void Server::FunctieThreadLucrator() {
  while (true) {
    function<void()> sarcina;

    {
      // Blocheaza mutex-ul inainte de a accesa coada
      unique_lock<mutex> blocare(mutex_coada);

      // Asteapta (doarme) pana cand apare o sarcina in coada
      conditie_trezire.wait(blocare, [this]() {
        return !coada_sarcini.empty() || opreste_serverul;
      });

      // Daca serverul se opreste si coada e goala, iesi din thread
      if (opreste_serverul && coada_sarcini.empty()) {
        return;
      }

      // Ia sarcina din fata cozii
      sarcina = move(coada_sarcini.front());
      coada_sarcini.pop();

    } // Mutex-ul se deblocheaza automat aici!

    // Executa sarcina in afara blocarii (ca alte threaduri sa acceseze coada)
    sarcina();
  }
}

// Helper pentru stergerea spatiilor (copiat din Retele/server.cpp)
string decupeaza_marginile(const string &text) {
  const string separatori = " \t\r\n";
  size_t inceput = text.find_first_not_of(separatori);
  if (inceput == string::npos) {
    return "";
  }
  size_t sfarsit = text.find_last_not_of(separatori);
  return text.substr(inceput, sfarsit - inceput + 1);
}

void Server::ProcseazaClient(int socket_client) {
  cout << "✓ Thread-ul " << this_thread::get_id() << " proceseaza clientul "
       << socket_client << endl;

  // Trimite mesaj de bun venit
  const char *mesaj_bun_venit = "Bun venit pe Serverul NMS!\n";
  send(socket_client, mesaj_bun_venit, strlen(mesaj_bun_venit), 0);

  string rest_comenzi;
  char buffer[4096];
  bool conectat = true;

  while (conectat) {
    memset(buffer, 0, sizeof(buffer));
    int bytes_cititi = recv(socket_client, buffer, sizeof(buffer) - 1, 0);

    if (bytes_cititi <= 0) {
      // Clientul s-a deconectat sau eroare
      break;
    }

    rest_comenzi.append(buffer, bytes_cititi);

    size_t pozitie_noua_linie;
    while ((pozitie_noua_linie = rest_comenzi.find('\n')) != string::npos) {
      string comanda_bruta = rest_comenzi.substr(0, pozitie_noua_linie);
      rest_comenzi.erase(0, pozitie_noua_linie + 1);

      string comanda_curata = decupeaza_marginile(comanda_bruta);
      if (comanda_curata.empty()) {
        continue;
      }

      cout << "📨 Primit de la " << socket_client << ": " << comanda_curata
           << endl;

      // Procesare comanda (stilul vechi adaptat la input curat)
      TipComanda tip = ProcesorComenzi::RecunoasteTipComanda(comanda_curata);
      string raspuns;

      switch (tip) {
      case LOGIN:
        raspuns = ProcesorComenzi::ProceseazaLOGIN(
            comanda_curata, socket_client, this->baza_date);
        break;
      case REGISTER:
        raspuns = ProcesorComenzi::ProceseazaREGISTER(
            comanda_curata, socket_client, this->baza_date);
        break;
      case HEARTBEAT:
        raspuns = ProcesorComenzi::ProceseazaHEARTBEAT(
            comanda_curata, socket_client, this->baza_date);
        break;
      case BATCH_EVENT:
        raspuns = ProcesorComenzi::ProceseazaBATCH_EVENT(
            comanda_curata, socket_client, this->baza_date);
        break;
      case NECUNOSCUT:
      default:
        // Incercam sa vedem daca e formatul "comanda : argument" specific
        // Retele Deocamdata raspundem cu eroare standard
        raspuns = "ERR Comanda necunoscuta";
        break;
      }

      // Trimite raspunsul
      if (!raspuns.empty()) {
        raspuns += "\n";
        int bytes_trimise =
            send(socket_client, raspuns.c_str(), raspuns.length(), 0);
        if (bytes_trimise < 0) {
          cerr << "Eroare la trimitere raspuns!" << endl;
          conectat = false;
          break;
        }
        cout << "📤 Trimis raspuns catre " << socket_client << " ("
             << bytes_trimise << " bytes)" << endl;
      }
    }
  }
  close(socket_client);
  cout << "✓ Clientul " << socket_client << " deconectat" << endl;
}

Server::~Server() {
  // Semnaleaza toate threadurile sa se opreasca
  opreste_serverul = true;
  conditie_trezire.notify_all();

  // Asteapta ca toate threadurile sa termine
  for (thread &t : threaduri_lucru) {
    if (t.joinable()) {
      t.join();
    }
  }
  close(socket_server);
  cout << "Server oprit" << endl;
}

void Server::AdaugaThreaduri(int numar) {
  for (int i = 0; i < numar; i++) {
    threaduri_lucru.emplace_back(&Server::FunctieThreadLucrator, this);
    threaduri_curente++;
  }
  cout << "Acum avem " << threaduri_curente << " threaduri" << endl;
}