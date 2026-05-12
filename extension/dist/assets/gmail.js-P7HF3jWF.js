(function(){const s={body:".a3s.aiL",sender:".gD",subject:"h2.hP"},c="data-cyberlang-banner",d="data-cyberlang-scanned",g=1e3;let u=0;function l(){const e=Date.now();if(e-u<g)return;const t=document.querySelector(s.body);if(!t||t.hasAttribute(d))return;const i=document.querySelector(s.sender),r=document.querySelector(s.subject);if(!i)return;t.setAttribute(d,"true"),u=e;const o={from_addr:i.getAttribute("email")||"",subject:(r==null?void 0:r.textContent.trim())||null,body_text:t.innerText||t.textContent||""};chrome.runtime.sendMessage({type:"EMAIL_CONTENT",payload:o},n=>{if(!chrome.runtime.lastError){if(!(n!=null&&n.ok)){h(t,n==null?void 0:n.error);return}x(t,n.result)}})}function b(e){var t;return((t=e.parentNode)==null?void 0:t.querySelector(`[${c}]`))!=null}function y(e){return e==="High Risk"?{bg:"#fee2e2",border:"#fca5a5",icon:"⚠️"}:e==="Medium Risk"?{bg:"#fef9c3",border:"#fbbf24",icon:"⚡"}:{bg:"#dcfce7",border:"#86efac",icon:"✓"}}function m({bg:e,border:t,color:i="#111",icon:r,html:o}){const n=document.createElement("div");return n.setAttribute(c,"true"),n.style.cssText=`
    padding: 10px 14px;
    margin: 8px 0;
    border-radius: 6px;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px;
    background: ${e};
    border: 1px solid ${t};
    color: ${i};
    display: flex;
    align-items: center;
    gap: 8px;
  `,n.innerHTML=`<span style="font-size: 18px;">${r}</span><span>${o}</span>`,n}function x(e,t){if(b(e))return;const{bg:i,border:r,icon:o}=y(t.riskLabel),n=t.matchedRules||[],f=n.length>0?`
      <div style="margin-top: 6px; font-size: 12px; color: #374151;">
        <strong>Why?</strong>
        <ul style="margin: 4px 0 0; padding-left: 18px;">
          ${n.slice(0,3).map(p=>`<li>${$(p)}</li>`).join("")}
        </ul>
        ${n.length>3?`<div style="margin-top: 4px; opacity: 0.7;">+ ${n.length-3} more</div>`:""}
      </div>
    `:"",a=document.createElement("div");a.setAttribute(c,"true"),a.style.cssText=`
    padding: 10px 14px;
    margin: 8px 0;
    border-radius: 6px;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px;
    background: ${i};
    border: 1px solid ${r};
    color: #111;
  `,a.innerHTML=`
    <div style="display: flex; align-items: center; gap: 8px;">
      <span style="font-size: 18px;">${o}</span>
      <span><strong>CyberLang:</strong> ${t.riskLabel} (${t.percentage}% phishing likelihood)</span>
    </div>
    ${f}
  `,e.parentNode.insertBefore(a,e)}function $(e){return typeof e=="string"?e:`${e.id}: ${e.description}`}function h(e,t){if(b(e))return;const i=t?`Couldn't scan this email — ${t}`:"Scanner server unavailable. Please try again later.",r=m({bg:"#fee2e2",border:"#fca5a5",color:"#991b1b",icon:"❌",html:`<strong>CyberLang:</strong> ${i}`});e.parentNode.insertBefore(r,e)}const T=new MutationObserver(()=>{l()});T.observe(document.body,{childList:!0,subtree:!0});l();
})()
