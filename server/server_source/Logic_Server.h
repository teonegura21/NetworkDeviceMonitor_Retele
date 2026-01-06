#pragma once
#include "../SQL.lite_db/db.h"
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

using namespace std;

class Server {
private:
  int min_threaduri;
  int max_threaduri;
  int threaduri_curente;
  int port;
  int socket_server;

  // Baza de date
  ManagerBazaDate *baza_date;

  // Componente pentru gestionarea threadurilor
  vector<thread> threaduri_lucru;
  queue<function<void()>> coada_sarcini;
  mutex mutex_coada;
  condition_variable conditie_trezire;
  bool opreste_serverul = false;

  // Metode private
  void InitializeazaServer();
  void InitializeazaPoolThreaduri();
  void FunctieThreadLucrator();
  void ProcseazaClient(int socket_client);
  void AdaugaThreaduri(int numar);

public:
  Server(int port, int min_threaduri, int max_threaduri, ManagerBazaDate *db);
  ~Server();
  void Ruleaza();
};