# Proiect_PSO

## Cerinte functionale

1. La inițializare, serverul va citi un fișier local de configurare care conține asocierile statice dintre nume de domenii (inclusiv subdomenii) și adrese IP.
2. Serverul va recunoaște și memora înregistrări de tip A (IPv4).
3. Dacă serverul primește o cerere pentru un domeniu care există în configurația sa locală, acesta va returna adresa IP corespunzătoare direct către client.
4. Dacă serverul primește o cerere pentru un domeniu care NU se află în fișierul său de configurare local, va redirecționa (forward) automat pachetul de cerere către un server DNS extern preconfigurat (ex. 8.8.8.8 sau 1.1.1.1).
5. Serverul va aștepta răspunsul de la serverul extern și, odată primit, va expedia acest răspuns înapoi către clientul inițial care a generat cererea.
6. Răspunsurile valide primite în urma procesului de forwarding vor fi salvate într-o memorie locală (cache), reținând numele domeniului, adresa IP și valoarea TTL (Time-To-Live) oferită de serverul extern.
7. La primirea unei noi cereri, serverul va verifica mai întâi existența domeniului în configurația locală. Dacă nu este găsit, va verifica prezența acestuia în cache înainte de a declanșa funcția de forwarding.
8. Dacă domeniul există în cache, serverul va returna adresa IP direct clientului.
9. Serverul va respecta timpul de expirare (TTL). Dacă o intrare din cache a depășit valoarea TTL (în secunde) de la momentul stocării ei, serverul o va considera invalidă. O nouă cerere pentru acel domeniu va forța serverul să reia procesul de forwarding pentru a prelua o valoare actualizată.
10. Serverul va rula continuu și va asculta cereri pe un socket UDP, portul 53.
11. Serverul va fi capabil să decodifice structura binară a unui pachet DNS pentru a extrage numele domeniului cerut.
12. Orice răspuns generat local va fi asamblat respectând structura binară a unui pachet DNS înainte de a fi transmis prin socket către client.
