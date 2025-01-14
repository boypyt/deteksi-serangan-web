# deteksi-serangan-web
by Henry Saptono

## cara pakai:
### Menjalankan waf

  $ sudo python demo_simple_waf.py

### Melihat log waf
  
  $ tail -f http_traffic.log

### Menguji menyerang

  $ curl -i -X POST http://127.0.0.1/data -d "q=' union select db()--'"

  $ curl -i -X GET "http://127.0.0.1/test?a=<script>alert()</script>"

  $ curl -i -X GET "http://127.0.0.1/test
  
