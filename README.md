# ScomToCa

<#
    Filter Alersts based on
    1) MoitoringRuleId
    2) MonitoringClassID
    #3) State = Kayit_ac
 
#>
```Xml
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsh="http://wsHarmoniIncident.ca.adk.ykb.com/">
<soap:Header/>
<soap:Body>
<wsh:CreateRequest>
<!--Optional:-->
<wsh:konuId>?</wsh:konuId>
<!--Optional:-->
<wsh:etkilenenKullanici>?</wsh:etkilenenKullanici>
<!--Optional:-->
<wsh:description>?</wsh:description>
<!--Optional:-->
<wsh:eklenecekDosya>cid:132587556599</wsh:eklenecekDosya>
<!--Optional:-->
<wsh:eklenecekDosyaAdi>?</wsh:eklenecekDosyaAdi>
<wsh:fonksiyonelEtki>?</wsh:fonksiyonelEtki>
<wsh:alansalEtki>?</wsh:alansalEtki>
<wsh:zKanal>?</wsh:zKanal>
<!--Optional:-->
<wsh:ekAlanlar>
<!--Zero or more repetitions:-->
<wsh:EkAlanlar>
<!--Optional:-->
<wsh:Value>?</wsh:Value>
<wsh:Key>?</wsh:Key>
</wsh:EkAlanlar>
</wsh:ekAlanlar>
</wsh:CreateRequest>
</soap:Body>
</soap:Envelope>
```
# Konuid, etkilenenKullanici, description, eklenecekDosya, eklenecekDosyaAdi,fonksiyonelEtki,alansalEtki,zKanal,ekAlanlar
$Proxy.CreateRequest("430980","scom",$content_Desc,"","","DisMusteriHizmetKesintisiYaratmaz","BazıIcMusterilerDisMusteriler","Scom",$ValuesObject)