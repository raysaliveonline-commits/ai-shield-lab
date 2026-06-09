/* script.js - Modular UI, charts, topology & SIP flow placeholders
   Goals:
   - Initialize charts lazily
   - Provide reusable UI helpers (loading states, toasts)
   - Render simple interactive topology and SIP call flow placeholders
   - Provide navigation and small accessibility helpers
*/

(() => {
  'use strict';

  // ---------- Utilities ----------
  const $ = sel => document.querySelector(sel);
  const $$ = sel => Array.from(document.querySelectorAll(sel));
  const debounce = (fn, ms=200) => { let t; return (...a)=>{clearTimeout(t);t=setTimeout(()=>fn(...a),ms)} };

  // Loading helpers
  function showLoading(el){
    if(!el) return;
    el.classList.add('loading');
    el.dataset.loading = '1';
  }
  function hideLoading(el){
    if(!el) return;
    el.classList.remove('loading');
    delete el.dataset.loading;
  }

  // Simple event bus for components
  const bus = { events: {}, on(k,fn){(this.events[k]||=(this.events[k]=[])).push(fn)}, emit(k,p){(this.events[k]||[]).forEach(f=>f(p))} };

  // ---------- Navigation ----------
  function bindNavigation(){
    const items = $$('.nav-item');
    items.forEach(a=>{
      a.addEventListener('click', e=>{
        e.preventDefault();
        const section = a.dataset.section;
        if(!section) return;
        // update active visual
        items.forEach(i=>i.classList.remove('active'));
        a.classList.add('active');
        // show panel
        $$('.panel').forEach(p=>p.classList.remove('active'));
        const panel = document.getElementById(section);
        if(panel) panel.classList.add('active');
        // emit event so panel-specific code can lazy-load
        bus.emit('panel:show', section);
      });
    });
  }

  // ---------- Time & small UI ----------
  function startClock(){
    const el = document.getElementById('current-time');
    if(!el) return;
    const fmt = (d)=>d.toLocaleString();
    el.textContent = fmt(new Date());
    setInterval(()=>el.textContent = fmt(new Date()), 60_000);
  }

  // ---------- Charts (Chart.js) ----------

  // Sample theme colors
  const palette = {
    background: '#07121a',
    green: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#00ff88',
    blue: getComputedStyle(document.documentElement).getPropertyValue('--accent-2').trim() || '#00d4ff',
    danger: getComputedStyle(document.documentElement).getPropertyValue('--danger').trim() || '#ff6b6b',
    muted: 'rgba(255,255,255,0.12)'
  };

  // Lazy init to improve startup
  const charts = {};
  function initThreatChart(){
    const ctx = document.getElementById('threatChart');
    if(!ctx || charts.threat) return;
    const data = {
      labels:['Malware','SIP Issues','NTP','QoS','Other'],
      datasets:[{
        data:[35,20,15,18,12],
        backgroundColor:[palette.danger,palette.green,palette.blue,'#8a6cff','#ffa94d'],
        borderWidth:0
      }]
    };
    charts.threat = new Chart(ctx,{
      type:'doughnut',
      data,
      options:{
        cutout: '60%',
        plugins:{legend:{position:'right',labels:{color:palette.muted}}},
        maintainAspectRatio:false
      }
    });
  }

  function initTimelineChart(){
    const ctx = document.getElementById('timelineChart');
    if(!ctx || charts.timeline) return;
    const labels = Array.from({length:12},(_,i)=>`${i*2}h`);
    charts.timeline = new Chart(ctx,{
      type:'line',
      data:{
        labels,
        datasets:[
          {label:'Network',data:labels.map(()=>Math.random()*50+30),borderColor:palette.blue,backgroundColor:'transparent',tension:0.3,pointRadius:0},
          {label:'Security Alerts',data:labels.map(()=>Math.random()*10+2),borderColor:palette.danger,backgroundColor:'transparent',tension:0.3,pointRadius:0}
        ]
      },
      options:{scales:{x:{grid:{display:false},ticks:{color:palette.muted}},y:{ticks:{color:palette.muted}}},plugins:{legend:{labels:{color:palette.muted}}},maintainAspectRatio:false}
    });
  }

  function initLatencyChart(){
    const ctx = document.getElementById('latencyChart'); if(!ctx) return;
    charts.latency = new Chart(ctx,{type:'line',data:{labels:['-5m','-4m','-3m','-2m','-1m','now'],datasets:[{label:'Latency ms',data:[50,42,48,45,46,45],borderColor:palette.blue,backgroundColor:'rgba(0,212,255,0.06)',tension:0.25} ]},options:{plugins:{legend:{display:false}},maintainAspectRatio:false}});
  }
  function initPacketLossChart(){ const ctx=document.getElementById('packetLossChart'); if(!ctx) return; charts.packet = new Chart(ctx,{type:'bar',data:{labels:['-5m','-4m','-3m','-2m','-1m','now'],datasets:[{label:'Packet Loss %',data:[0.1,0.12,0.08,0.11,0.09,0.12],backgroundColor:palette.green}]},options:{plugins:{legend:{display:false}},maintainAspectRatio:false}}) }
  function initBandwidthChart(){ const ctx=document.getElementById('bandwidthChart'); if(!ctx) return; charts.band = new Chart(ctx,{type:'doughnut',data:{labels:['Used','Free'],datasets:[{data:[62.5,37.5],backgroundColor:[palette.green,'rgba(255,255,255,0.04)']}]},options:{cutout:'70%',plugins:{legend:{display:false}},maintainAspectRatio:false}}) }

  // ---------- Topology renderer (simple SVG interactive) ----------
  function renderTopology(){
    const container = document.getElementById('topology');
    if(!container || container.dataset.rendered) return;
    container.dataset.rendered = '1';
    // simple SVG creation
    const svgns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgns,'svg');
    svg.setAttribute('width','100%'); svg.setAttribute('height','100%'); svg.setAttribute('viewBox','0 0 800 400');
    // sample nodes and links
    const nodes = [
      {id:'gw',x:400,y:40,label:'Gateway'},
      {id:'sip1',x:150,y:180,label:'SIP-Primary'},
      {id:'sip2',x:650,y:180,label:'SIP-Secondary'},
      {id:'db',x:400,y:320,label:'DB/Call-Store'}
    ];
    const links = [['gw','sip1'],['gw','sip2'],['sip1','db'],['sip2','db']];
    // draw links
    links.forEach(l=>{
      const a=nodes.find(n=>n.id===l[0]), b=nodes.find(n=>n.id===l[1]);
      const line=document.createElementNS(svgns,'line');
      line.setAttribute('x1',a.x); line.setAttribute('y1',a.y); line.setAttribute('x2',b.x); line.setAttribute('y2',b.y);
      line.setAttribute('stroke','rgba(255,255,255,0.06)'); line.setAttribute('stroke-width','2');
      svg.appendChild(line);
    });
    // draw nodes
    nodes.forEach(n=>{
      const g=document.createElementNS(svgns,'g'); g.setAttribute('transform',`translate(${n.x-40},${n.y-20})`);
      const rect=document.createElementNS(svgns,'rect'); rect.setAttribute('width','120'); rect.setAttribute('height','40'); rect.setAttribute('rx','8');
      rect.setAttribute('fill','rgba(255,255,255,0.02)'); rect.setAttribute('stroke','rgba(255,255,255,0.04)');
      const text=document.createElementNS(svgns,'text'); text.setAttribute('x','60'); text.setAttribute('y','25'); text.setAttribute('text-anchor','middle'); text.setAttribute('fill','#bcd7e8'); text.setAttribute('font-size','12');
      text.textContent = n.label;
      g.appendChild(rect); g.appendChild(text);
      g.style.cursor='pointer';
      g.addEventListener('mouseenter',()=>{rect.setAttribute('fill','rgba(0,255,136,0.06)')});
      g.addEventListener('mouseleave',()=>{rect.setAttribute('fill','rgba(255,255,255,0.02)')});
      svg.appendChild(g);
    });
    container.appendChild(svg);
  }

  // ---------- SIP flow renderer (simple swimlane) ----------
  function renderSipFlow(){
    const container = document.getElementById('sip-flow');
    if(!container || container.dataset.rendered) return;
    container.dataset.rendered = '1';
    // create a simple horizontal swimlane with events
    const flow = document.createElement('div');
    flow.style.display='flex'; flow.style.gap='18px'; flow.style.padding='8px'; flow.style.justifyContent='space-around';
    const legs = ['Caller','Proxy','Gateway','Callee'];
    legs.forEach(l=>{
      const col = document.createElement('div'); col.style.flex='1'; col.style.textAlign='center';
      const title = document.createElement('div'); title.textContent=l; title.style.fontWeight=700; title.style.marginBottom='8px';
      col.appendChild(title);
      // sample messages
      ['INVITE','100 Trying','180 Ringing','200 OK'].forEach((m,i)=>{
        const msg = document.createElement('div');
        msg.textContent = m;
        msg.style.background = i%2? 'rgba(255,255,255,0.02)': 'rgba(0,212,255,0.02)';
        msg.style.padding='6px 8px'; msg.style.margin='6px 0'; msg.style.borderRadius='8px'; msg.style.cursor='default';
        msg.addEventListener('mouseenter',()=>{msg.style.transform='scale(1.02)';msg.style.boxShadow='0 6px 18px rgba(0,0,0,0.6)'});
        msg.addEventListener('mouseleave',()=>{msg.style.transform='none';msg.style.boxShadow='none'});
        col.appendChild(msg);
      });
      flow.appendChild(col);
    });
    container.appendChild(flow);
  }

  // ---------- Bindings & Lazy init ----------
  function bindPanelLazyLoading(){
    bus.on('panel:show', section=>{
      // initialize only when visible
      if(section === 'overview'){
        initThreatChart(); initTimelineChart();
      }
      if(section === 'network'){
        initLatencyChart(); initPacketLossChart(); initBandwidthChart(); renderTopology();
      }
      if(section === 'voice'){
        renderSipFlow();
      }
      if(section === 'rtp'){
        // other inits if needed
      }
    });
    // trigger current active panel init
    const active = document.querySelector('.panel.active');
    if(active) bus.emit('panel:show', active.id);
  }

  // ---------- Small interactions ----------
  function bindHeaderActions(){
    document.querySelectorAll('[data-action="refresh"]').forEach(btn=>{
      btn.addEventListener('click', e=>{
        btn.classList.add('animating');
        setTimeout(()=>btn.classList.remove('animating'),800);
        const tgt = btn.dataset.target;
        // sample: show a tiny loading overlay on target panel
        const panel = document.getElementById(tgt);
        if(panel){ showLoading(panel); setTimeout(()=>hideLoading(panel),800) }
      });
    });
    // search debounce
    const search = document.getElementById('search-input');
    if(search) search.addEventListener('input', debounce((e)=>{ console.log('search:', e.target.value) }, 250));
  }

  // ---------- Init on DOM ready ----------
  document.addEventListener('DOMContentLoaded', () => {
    bindNavigation();
    startClock();
    bindPanelLazyLoading();
    bindHeaderActions();
  });

  // expose for debugging
  window.AIShield = {charts, renderTopology, renderSipFlow};
})();
