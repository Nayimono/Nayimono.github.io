// === KR-robust databoard.js ===
const log=(...a)=>console.log('[DB]',...a);
const toNum=(v,d=0)=>{if(v==null)return d;const n=parseFloat(String(v).replace(/[, ]/g,''));return isNaN(n)?d:n;};
const monthKey=d=>{const t=new Date(d);return isNaN(t)?null:(t.getFullYear()+'-'+String(t.getMonth()+1).padStart(2,'0'));};
const median=a=>{if(!a.length)return 0;const s=[...a].sort((x,y)=>x-y);const m=Math.floor(s.length/2);return s.length%2?s[m]:(s[m-1]+s[m])/2;};
const fmt=n=>Number(n||0).toLocaleString('ko-KR');
const risk=(rec,sens,method)=>{const w={'malware/server intrusion':1.3,'server hacking':1.2,'sql injection':1.1,'credential stuffing':1.1,'posting/mis-send (human error)':0.8,'system error (api/code deploy)':0.9}[String(method||'').toLowerCase()]||1.0;const base=Math.log10(1+Math.max(1,rec));return Math.min(100,Math.round(base*20*Math.max(1,sens)*w));};

// 헤더/국가 정규화
const headerMap={'date':'date','날짜':'date','일자':'date','organization':'organization','기관':'organization','조직':'organization','회사':'organization','country':'country','국가':'country','sector':'sector','부문':'sector','산업':'sector','업종':'sector','method':'method','유형':'method','방법':'method','원인':'method','records':'records','레코드':'records','건수':'records','노출수':'records','피해규모':'records','sensitivity':'sensitivity','민감도':'sensitivity','중요도':'sensitivity','days_to_discovery':'days_to_discovery','발견까지일수':'days_to_discovery','발견일수':'days_to_discovery','탐지일수':'days_to_discovery','source':'source','출처':'source','링크':'source'};
const normCountry=v=>{const s=String(v||'').trim().toLowerCase();const map=new Map([['kr','KR'],['kor','KR'],['korea','KR'],['south korea','KR'],['republic of korea','KR'],['대한민국','KR'],['한국','KR']]);return map.get(s)||(s.toUpperCase()==='KR'?'KR':s.toUpperCase());};

const showError=(msg)=>{let box=document.getElementById('errorBox');if(!box){box=document.createElement('div');box.id='errorBox';box.style.cssText='margin-top:12px;padding:10px;border:1px solid #fbb;background:#fee;color:#b00;border-radius:8px';document.body.appendChild(box);}box.textContent=msg;};

function loadRows(){
  return new Promise((resolve,reject)=>{
    Papa.parse(DATA_URL,{download:true,header:true,skipEmptyLines:true,dynamicTyping:false,
      complete:(res)=>{
        if(!res||!res.data){reject('CSV parse error');return;}
        let rowsRaw=res.data.filter(r=>{const onlyKey=Object.keys(r).length===1?Object.keys(r)[0]:'';return !/^sep\\s*=/.test(onlyKey||'');});
        const normalizeKey=k=>String(k||'').replace(/^\\ufeff/,'').trim().toLowerCase();
        const rows=rowsRaw.map(obj=>{const o={};Object.keys(obj).forEach(k=>{const nk=headerMap[normalizeKey(k)]||normalizeKey(k);o[nk]=typeof obj[k]==='string'?obj[k].trim():obj[k];});return o;});
        const fixed=rows.map(r=>({date:r.date||'',
          organization:r.organization||'',country:normCountry(r.country),sector:r.sector||'',method:r.method||'',
          records:toNum(r.records,0),sensitivity:toNum(r.sensitivity,1),days_to_discovery:toNum(r.days_to_discovery,0),source:r.source||''}));
        let filtered=fixed;
        if(typeof COUNTRY_ONLY!=='undefined'&&COUNTRY_ONLY){filtered=fixed.filter(x=>normCountry(x.country)==='KR');}
        log('parsed:',rowsRaw.length,'rows / after filter:',filtered.length);
        resolve({rows:filtered, all:fixed});
      },
      error:(err)=>reject(err)
    });
  });
}

function draw(rows){
  const totalIncidents=rows.length;
  if(!totalIncidents){showError('표시할 데이터가 없습니다. (CSV 비어있음/헤더 불일치/country가 KR 아님)');}
  const totalRecords=rows.reduce((a,b)=>a+(b.records||0),0);
  const avgRecords=totalIncidents?Math.round(totalRecords/totalIncidents):0;

  const dates=rows.map(r=>new Date(r.date)).filter(d=>!isNaN(d));
  const minD=dates.length?new Date(Math.min(...dates)):null;
  const maxD=dates.length?new Date(Math.max(...dates)):null;
  document.getElementById('period').textContent=(minD&&maxD)?`${minD.toISOString().slice(0,10)} ~ ${maxD.toISOString().slice(0,10)}`:'-';
  document.getElementById('totalIncidents').textContent=fmt(totalIncidents);
  document.getElementById('totalRecords').textContent=fmt(totalRecords);
  document.getElementById('avgRecords').textContent=fmt(avgRecords);

  const byMethod={}; rows.forEach(r=>byMethod[r.method]=(byMethod[r.method]||0)+1);
  const mKeys=Object.keys(byMethod), mVals=mKeys.map(k=>byMethod[k]);
  const topIdx=mVals.length?mVals.indexOf(Math.max(...mVals)):-1;
  if(topIdx>=0){
    document.getElementById('topMethod').textContent=mKeys[topIdx]||'-';
    document.getElementById('topMethodPct').textContent=((mVals[topIdx]/totalIncidents)*100).toFixed(1)+'%';
  }

  let top={risk:0,row:null}; rows.forEach(r=>{const v=risk(r.records,r.sensitivity,r.method);if(v>top.risk)top={risk:v,row:r};});
  document.getElementById('topCase').textContent=top.row?`${top.row.organization} (${fmt(top.row.records)}건)`:'-';
  echarts.init(document.getElementById('gaugeRisk')).setOption({series:[{type:'gauge',min:0,max:100,progress:{show:true,width:12},axisLine:{lineStyle:{width:12}},axisTick:{show:false},splitLine:{length:10},axisLabel:{distance:15},detail:{valueAnimation:true,formatter:'{value}',fontSize:28},data:[{value:top.risk}]}]});
  echarts.init(document.getElementById('byMethod')).setOption({tooltip:{},xAxis:{type:'category',data:mKeys},yAxis:{type:'value'},series:[{type:'bar',data:mVals,itemStyle:{color:'#FF6B6B'}}]});

  const monthly={}; rows.forEach(r=>{const k=monthKey(r.date); if(!k)return; (monthly[k]||(monthly[k]={count:0,recs:[]})).count++; monthly[k].recs.push(r.records||0);});
  const months=Object.keys(monthly).sort(), counts=months.map(m=>monthly[m].count), medRec=months.map(m=>median(monthly[m].recs));
  echarts.init(document.getElementById('trend')).setOption({tooltip:{trigger:'axis'},xAxis:{type:'category',data:months},yAxis:[{type:'value',name:'건수'},{type:'value',name:'중위 레코드',position:'right'}],series:[{name:'건수',type:'bar',data:counts,itemStyle:{color:'#4E79A7'}},{name:'중위 레코드',type:'line',yAxisIndex:1,data:medRec,smooth:true,itemStyle:{color:'#F28E2B'}}]});

  const sData=rows.map(r=>({name:r.organization,value:[r.days_to_discovery||0,r.records||0,r.sensitivity||1]}));
  echarts.init(document.getElementById('scatter')).setOption({tooltip:{formatter:p=>`${p.name}<br>발견까지: ${p.value[0]}일<br>노출: ${fmt(p.value[1])}건<br>민감도: ${p.value[2]}`},xAxis:{name:'발견까지 일수'},yAxis:{name:'노출 레코드'},series:[{type:'scatter',symbolSize:v=>Math.max(8,(v[2]||1)*10),data:sData,itemStyle:{color:'#59A14F'}}]});

  const bySector={}; rows.forEach(r=>bySector[r.sector]=(bySector[r.sector]||0)+(r.records||0));
  const top10=Object.entries(bySector).sort((a,b)=>b[1]-a[1]).slice(0,10);
  echarts.init(document.getElementById('topSector')).setOption({grid:{left:100},xAxis:{type:'value'},yAxis:{type:'category',data:top10.map(x=>x[0]),inverse:true},series:[{type:'bar',data:top10.map(x=>x[1]),itemStyle:{color:'#E15759'}}]});
}

(async()=>{
  try{
    const {rows, all}=await loadRows();
    if(!rows.length){
      const uniques=[...new Set(all.map(x=>x.country))].join(', ') || '(country 값 없음)';
      showError(`KR 필터 결과 0건. CSV의 country 값 확인: [${uniques}]`);
    }
    draw(rows);
  }catch(e){
    console.error(e);
    showError('CSV 로드 실패. 경로 또는 배포 상태를 확인해 주세요.');
  }
