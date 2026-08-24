const stories=[
{tag:"AI",title:"AI is changing how we build software",text:"The latest generation of AI tools is reshaping coding, research and everyday workflows.",date:"Today"},
{tag:"CYBERSECURITY",title:"Why zero-trust security keeps growing",text:"Organizations are moving toward identity-first security as threats become more automated.",date:"Today"},
{tag:"GADGETS",title:"The next wave of personal devices",text:"Smaller, smarter and more connected hardware is changing the way people interact with technology.",date:"Today"},
{tag:"STARTUPS",title:"The tools making startups faster",text:"Cloud platforms and AI automation are lowering the cost of launching new products.",date:"Yesterday"},
{tag:"PROGRAMMING",title:"Web development keeps getting simpler",text:"Modern browser APIs and lightweight frameworks are making powerful web apps easier to ship.",date:"Yesterday"},
{tag:"FUTURE",title:"What computing could look like next",text:"From edge computing to new interfaces, the future of computing is becoming more distributed.",date:"2 days ago"}
];
function render(list=stories){document.getElementById("news").innerHTML=list.map(s=>`<article class="card"><div class="tag">${s.tag}</div><h3>${s.title}</h3><p>${s.text}</p><div class="meta">${s.date} · 4 min read</div></article>`).join("")}
function filterNews(){const q=document.getElementById("search").value.toLowerCase();render(stories.filter(s=>(s.title+s.text+s.tag).toLowerCase().includes(q)))}
function shuffle(){render([...stories].sort(()=>Math.random()-.5))}
document.getElementById("search").addEventListener("input",filterNews);
document.getElementById("theme").onclick=()=>{document.body.classList.toggle("dark");document.getElementById("theme").textContent=document.body.classList.contains("dark")?"☀":"☾"};
document.getElementById("year").textContent=new Date().getFullYear();render();