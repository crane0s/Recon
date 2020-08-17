#!/bin/bash

echo Script de rec0n by crane0s
echo Modo de Uso: ./rec0n.sh {target}
sleep 5


#COLORS
NORMAL="\e[0m"
GREEN="\e[92m"


echo -e "${GREEN}[+]Start Subdomain Enumeretion"

#Assetfinder
echo -e "${GREEN}[+] Starting Assetfinder"
assetfinder --subs-only $1 |sort -u |tee assetfinder.txt

#Sublist3r
echo -e "${GREEN}[+] Starting Sublist3r"
python /home/crane0s/tools/Sublist3r/sublist3r.py -d $1 -o sublist3r.txt

#subfinder
echo -e "${GREEN}[+] Starting subfinder"
subfinder -d $1 >> subfinder.txt

#amass
echo -e "${GREEN}[+] Starting amass"
amass enum -norecursive -noalts -d $1 >> amass.txt

#censys-subdomain-finder
echo -e "${GREEN}[+] Starting censys-subdomain-finder"
export CENSYS_API_ID=df6b110e-33b0-4361-adee-d5f2adfff64e
export CENSYS_API_SECRET=zfFDwzAJBBoG1jQ9aL267WyqJH0yrlsG
python /home/crane0s/tools/censys-subdomain-finder/censys_subdomain_finder.py $1 -o censys.txt

#Filtering
echo -e "${GREEN}[+] Starting Filtering"
cat sublist3r.txt assetfinder.txt amass.txt subfinder.txt censys.txt | sort -u |uniq -u| grep -v "*" |sort -u|tee $1-Final-Subs.txt

#Httprobe
echo -e "${GREEN}[+] Starting Httprobe"
cat $1-Final-Subs.txt |sort -u |uniq -u|httprobe|tee $1-alive.txt

#Get-Tilie
echo -e "${GREEN}[+]Start Get-titles"
cat $1-alive.txt|get-title

#subjack - subzy
echo -e "${GREEN}[+]Start Subdomain Takeover Scan"
subjack -w $1-Final-Subs.txt -t 20 -ssl -c /root/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o subjack.txt
subzy -targets $1-Final-Subs.txt -hide_fails --verify_ssl -concurrency 20 | sort -u | tee "subzy.txt"

#Aquatone
echo -e "${GREEN}[+]Aquatone Screenshot"
#cat $1-alive.txt| aquatone -screenshot-timeout 10 -out screenshots/

echo -e "${GREEN}[+] Numbero de Domains: "&cat $1-Final-Subs.txt | wc -l
echo -e "${GREEN}[+] Numbero de Urls: "&cat $1-alive.txt | wc -l

echo -e "${GREEN}[+] Borrando cache ....... "
rm sublist3r.txt assetfinder.txt amass.txt subfinder.txt censys.txt

sleep 3

domain=$1-alive.txt

#Gau
echo -e "${GREEN}[+]gau Scan Started..."
cat $domain | gau | sort | uniq >> gau_urls.txt

#waybackurls
echo -e "${GREEN}[+]waybackurls Scan Started"
cat $domain | waybackurls | sort | uniq >> archiveurl.txt

#gospider

cat gau_urls.txt archiveurl.txt |  sort -u > waybackurls.txt
rm archiveurl.txt && rm gau_urls.txt

echo -e "${GREEN}[+]total waybackurls"
cat waybackurls.txt | wc -l

#Gf
echo  -e "${GREEN}Buscando endpoints vulnerables............................."
mkdir paramlist
cat waybackurls.txt | gf redirect > paramlist/redirect.txt 
cat waybackurls.txt | gf ssrf > paramlist/ssrf.txt 
cat waybackurls.txt | gf rce > paramlist/rce.txt 
cat waybackurls.txt | gf idor > paramlist/idor.txt 
cat waybackurls.txt | gf sqli > paramlist/sqli.txt 
cat waybackurls.txt | gf lfi > paramlist/lfi.txt
cat waybackurls.txt | gf ssti > paramlist/ssti.txt 
cat waybackurls.txt | gf debug_logic > paramlist/debug_logic.txt 
cat waybackurls.txt | gf interestingsubs > paramlist/interestingsubs.txt
cat waybackurls.txt | gf img-traversal > paramlist/img-traversal.txt
cat waybackurls.txt | grep "?" | sort | qsreplace "" | grep "=" >> paramlist/paramlist.txt
echo "Gf patters Completed"

echo  -e "${GREEN}Buscando Links Rotos"
cat waybackurls.txt | egrep -iv ".(jpg|gif|css|png|woff|pdf|svg|js)" | burl | grep 200 | egrep -v "404" | tee brokenlink.txt

#Hakrawler
echo  -e "${GREEN}Buscando JS"
cat waybackurls.txt | grep -iE "\.js$" | sort | uniq | httpx -silent -o  Js-temp1.txt
hakrawler -js -url $1-alive.txt -plain -depth 2 -scope strict -insecure > Js-temp2.txt
cat $1-alive.txt | subjs >> Js-temp3.txt
cat Js-temp1.txt Js-temp2.txt Js-temp3.txt | sort | uniq >> Js-Files.txt
rm Js-temp1.txt && rm Js-temp2.txt && rm Js-temp3.txt
cat $1-alive.txt | while read url;do python3 /home/crane0s/tools/LinkFinder/linkfinder.py -i $url -d -o cli ; done > jsendpoints.txt
cat Js-Files.txt | while read url;do python3 /home/crane0s/tools/secretfinder/SecretFinder.py -i $url -o cli ; done > jslinksecret.txt

#Nuclei
echo  -e "${GREEN}Buscando CVES"
nuclei -l $1-alive.txt -t /home/crane0s/tools/nuclei-templates/cves/ -o $-CVES-results.txt
echo  -e "${GREEN}Buscando SSFR"
nuclei -l paramlist/ssrf.txt -t /home/crane0s/tools/nuclei-templates/vulnerabilities/microstrategy-ssrf.yaml -o $-SSRF-results.txt
echo  -e "${GREEN}Buscando Openredirect"
nuclei -l paramlist/redirect.txt -t /home/crane0s/tools/nuclei-templates/vulnerabilities/open-redirect.yaml -o $-Openredirect-results.txt
echo  -e "${GREEN}Buscando RCE rshellshock-user-agent"
nuclei -l $1-alive.txt -t /home/crane0s/tools/nuclei-templates/vulnerabilities/rce-shellshock-user-agent.yaml -o $-rceshellshock-results.txt
echo  -e "${GREEN}Buscando x-forwarded-host-injection"
nuclei -l $1-alive.txt -t /home/crane0s/tools/nuclei-templates/vulnerabilities/x-forwarded-host-injection.yaml -o $-Hostinjection-results.txt
echo  -e "${GREEN}Buscando crlf-injection"
nuclei -l $1-alive.txt -t /home/crane0s/tools/nuclei-templates/vulnerabilities/crlf-injection.yaml -o $-crlfinjection-results.txt
echo  -e "${GREEN}Buscando Xss"
nuclei -l paramlist/paramlist.txt -t /home/crane0s/tools/nuclei-templates/basic-detections/basic-xss-prober.yaml -o $-XSS-results.txt


#Wafw00f
echo "${GREEN}Probando wafw00f ver resutados waf.txt"
wafw00f -i $domain -o waf.txt

echo "${NORMAL} Buena Suerte"
