# deteksi-serangan-web
by Henry Saptono

Simulasi penerapan AI dalam keamanan siiber menggunakan teknik Machine Learning berbasis Supervised Learning menggunakan model Random Forest


## cara pakai:
### Menjalankan waf

Sebelum menjalakan pastikan model ML sudah terbentuk dan pastikan lokasi / path file nya benar pada kode

  $ sudo python demo_simple_waf.py

### Melihat log waf
  
  $ tail -f http_traffic.log

### Menguji menyerang

Sebelumnya diasumsikan pada komputer lokal Anda sudah berjalan web server (nginx atau apache atau yang lainnya)

  $ curl -i -X POST http://127.0.0.1/data -d "q=' union select db()--'"

  $ curl -i -X GET "http://127.0.0.1/test?a=<script>alert()</script>"

  $ curl -i -X GET "http://127.0.0.1/test
  
