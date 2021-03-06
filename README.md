# SCANNER

Hópur 17: Spritt og sápa
- Almar Teitsson (alt15)
- Björgvin Hall (bjh45)
- Emma Líf Jónsdóttir (elj44)

### Tilgangur með forriti: 
   Tilgangurinn með forritinu er að skanna net og sjá hvaða port eru opin. Þeir sem myndu nota það væru 
   einhver sem væri að sjá um öryggi eða einhver sem ætlar að gera árás á serverinn.
   Það eru margar stillingar sem hægt er að nota hér fyrir neðan er farið yfir allar stillingarnar.
   
### Syn scanning:
   Tilgangurinn með syn scanning er að skoða hvernig samskipti port eru að hafa án þess að 
   opna tengingu við serverinn. Það er gert þannig að það sendir SYN pakka á öll portin hjá 
   ákveðnum server ef serverinn sendir tilbaka SYN-ACK pakka þá vitum við að það ákveðna 
   port er opið og ef portið er opið sendum við RST pakka svo serverinn heldur að eitthvað
   hafi komið uppá og við höfum hætt við að tengjast. En ef serverinn svarar SYN pakkanum með 
   RST þá vitum við að það port er lokað.
   
### Low and slow:
   Tilgangurinn með low and slow scan-i er að komast að því hvaða port eru opin án þess 
   að serverinn taki eftir því að verið sé að skoða það. 
   
   

### Leiðbeiningar um keyrslu:
   Nota skal python3 til að keyra forritið og hafa scapy pakkann á vélinni 
   Til að nota scapy þarf að skrifa sudo fremst (ef á windows þá þarf að keyra sem administrator)
   input-in sem eru tekin inn eru þrjú en það er hostname,lowport og highport. Það
   eru mismunandi stillingar sem hægt er að nota en hér fyrir neðan er farið yfir þær.
   
   hostname: 
      Ef hostname inniheldur "/" þá prentast út CIDR range af ip tölum
      Ef hostname inniheldur "-" skannar ip tölur á ákveðnu bili. 
      Ef hostname er "0" er lesið ip tölur úr ipaddresses.txt.
   
   lowport and highport:
      Ef lowport og highport eru ekki bæði 0 þá er tekið bilið þar á milli og tékkað á þeim portum.
      Ef lowport og highport eru bæði 0 þá er notað algengustu portin en þau eru í skjalinu ports.txt
      
   Forritið er hægt að keyra með mörgum stillingum. Þegar forritið er keyrt kemur upp spurning um hvort eigi að notast við 
   low and slow scan eða ekki. Þá er valið 1 fyrir low and slow scan og 2 ef það á að nota normal scan. Ef valið er 2 er 
   svo spurt hvort portin eigi að vera í hækkandi röð eða í random röð. Eftir að búið er að setja inn svar við þessum 
   spurningum er svo spurt hvort eigi að nota SYN scan eða nota normal scan. Síðasta spurningin eru svo hvort eigi að 
   birta closed port eða ekki til að birta þau er valið 1. 
   
   Þá eru allar stillingar komnar og scan-ið fer 
   í gang og prentast út 
 

### Skrár:

   scanner.py        - grind fyrir skanner
   test.sh           - bash scripta til að prófa skanner
   ports.txt         - listi af 50 helstu portum 
   ipaddresses.txt   - listi af ip tölum 
   requirements.txt   - listi af pökkum sem þarf að hafa til að keyra forritið
   
