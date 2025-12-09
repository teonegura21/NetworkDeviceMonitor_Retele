#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std;

class Client {
private:
  int socket_client;
  string adresa_server;
  int port_server;
  bool conectat;
  mutex mtx_comunicare; // Mutex pentru a proteja scrierea pe socket

public:
  Client(string adresa, int port)
      : adresa_server(adresa), port_server(port), conectat(false) {}

  bool Conecteaza() {
    // Creaza socket
    socket_client = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_client < 0) {
      cerr << "Eroare la crearea socket-ului!" << endl;
      return false;
    }

    // Configureaza adresa serverului
    struct sockaddr_in adresa_srv;
    adresa_srv.sin_family = AF_INET;
    adresa_srv.sin_port = htons(port_server);

    if (inet_pton(AF_INET, adresa_server.c_str(), &adresa_srv.sin_addr) <= 0) {
      cerr << "Adresa invalida!" << endl;
      return false;
    }

    // Conecteaza la server
    if (connect(socket_client, (struct sockaddr *)&adresa_srv,
                sizeof(adresa_srv)) < 0) {
      cerr << "Eroare la conectare!" << endl;
      return false;
    }

    conectat = true;
    cout << "✓ Conectat la server " << adresa_server << ":" << port_server
         << endl;

    // Citeste mesajul de bun venit
    char buffer[1024];
    int bytes = recv(socket_client, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
      buffer[bytes] = '\0';
      cout << "Server: " << buffer;
    }

    return true;
  }

  void TrimiteText(const string &mesaj) {
    lock_guard<mutex> lock(mtx_comunicare); // Protejam scrierea
    string mesaj_final = mesaj + "\n";      // Adaugam newline ca delimitator
    send(socket_client, mesaj_final.c_str(), mesaj_final.length(), 0);
    // cout << "📤 Trimis: " << mesaj << endl; // Comentat ca sa nu spamam
    // consola
  }

  string PrimesteRaspuns() {
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    // NOTA: recv e blocant. Daca avem mai multe threaduri care asteapta
    // raspuns, e complicat. Pentru acest stadiu, presupunem ca doar threadul
    // principal asteapta raspuns la comenzi explicite. Logurile trimise din
    // fundal NU asteapta raspuns (fire and forget).

    int bytes = recv(socket_client, buffer, sizeof(buffer) - 1, 0);

    if (bytes <= 0) {
      conectat = false;
      return "";
    }

    // Simplu: returnam tot ce am primit (fara \n de la final daca exista)
    string raspuns(buffer, bytes);
    if (!raspuns.empty() && raspuns.back() == '\n') {
      raspuns.pop_back();
    }
    return raspuns;
  }

  void MonitorizeazaLog(const string &cale_fisier) {
    cout << "📡 Pornire monitorizare background: " << cale_fisier << endl;

    FILE *pipe = fopen(cale_fisier.c_str(), "r");
    if (!pipe) {
      cerr << "Eroare la deschiderea fisierului de log! (Rulezi cu sudo?)"
           << endl;
      return;
    }

    // Mergem la sfarsitul fisierului pentru a citi doar ce apare NOU
    fseek(pipe, 0, SEEK_END);
    long pozitie_curenta = ftell(pipe);

    char buffer[1024];

    while (conectat) {
      // Resetam pozitia si incercam sa citim
      fseek(pipe, 0, SEEK_END);
      long marime_noua = ftell(pipe);

      if (marime_noua > pozitie_curenta) {
        fseek(pipe, pozitie_curenta, SEEK_SET);

        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
          string linie(buffer);
          // Eliminam newline de la final
          if (!linie.empty() && linie.back() == '\n')
            linie.pop_back();

          if (!linie.empty()) {
            // Impachetam in comanda BATCH_EVENT
            string comanda = "BATCH_EVENT " + linie;
            TrimiteText(comanda);
          }
        }
        pozitie_curenta = ftell(pipe);
      }

      // Asteptam putin inainte de urmatoarea verificare (polling)
      usleep(500000); // 0.5 secunde
    }

    fclose(pipe);
    cout << "Monitorizare oprita." << endl;
  }

  bool IsConnected() const { return conectat; }

  void Deconecteaza() {
    if (conectat) {
      conectat = false;
      close(socket_client);
      cout << "🔌 Deconectat." << endl;
    }
  }

  // Porneste firul de executie pentru monitorizare (non-blocant)
  void PornesteMonitorizare() {
    thread thread_monitor(
        [this]() { this->MonitorizeazaLog("/var/log/syslog"); });
    thread_monitor.detach();
  }

  void Ruleaza() {
    // Pornim thread-ul de monitorizare automat
    thread thread_monitor(
        [this]() { this->MonitorizeazaLog("/var/log/syslog"); });
    thread_monitor.detach(); // Il lasam sa ruleze in fundal independent

    cout << "\n=== Client NMS ===" << endl;
    cout << "Comenzi disponibile:" << endl;
    cout << "  1 - Trimite REGISTER" << endl;
    cout << "  2 - Trimite HEARTBEAT" << endl;
    cout << "  3 - Trimite BATCH_EVENT (Manual)" << endl;
    cout << "  exit - Iesi" << endl;
    cout << "==================\n" << endl;

    string comanda;
    while (conectat) {
      cout << "> ";
      getline(cin, comanda);

      if (comanda == "exit") {
        conectat = false; // Asta va opri si threadul de monitorizare
        break;
      }

      string instructiune;

      if (comanda == "1") {
        instructiune = "REGISTER 1.0 test-client Linux";
      } else if (comanda == "2") {
        instructiune = "HEARTBEAT 3600";
      } else if (comanda == "3") {
        instructiune = "BATCH_EVENT 1";
      } else {
        cout << "Comanda necunoscuta! Incearca 1, 2, 3 sau exit" << endl;
        continue;
      }

      // Trimite mesajul
      TrimiteText(instructiune);

      // Asteapta raspunsul
      string raspuns = PrimesteRaspuns();
      if (conectat) {
        cout << "📥 Raspuns: " << raspuns << endl;
      } else {
        cout << "Conexiune inchisa de server" << endl;
        break;
      }
    }
  }
  ~Client() {
    if (conectat) {
      close(socket_client);
      cout << "Deconectat de la server" << endl;
    }
  }
};
