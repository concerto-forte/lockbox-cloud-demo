import { argon2id } from "https://cdn.jsdelivr.net/npm/hash-wasm@4.12.0/+esm";

let encryptionKey = null, token = localStorage.getItem("lockbox_token") || null;
const $ = id => document.getElementById(id);
const b64 = bytes => btoa(String.fromCharCode(...bytes));
const unb64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
function say(msg, bad=false) { $("status").textContent = msg; $("status").style.color = bad ? "#ffb4b4" : "#b9d9b4"; }
async function derive(password, salt) {
  // Master password chỉ được sử dụng trong Web Worker/WASM của browser, không đưa vào API request.
  const root = await argon2id({password, salt, parallelism: 1, iterations: 3, memorySize: 65536, hashLength: 32, outputType: "binary"});
  const material = await crypto.subtle.importKey("raw", root, "HKDF", false, ["deriveBits", "deriveKey"]);
  const info = new TextEncoder();
  const authBits = await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt,info:info.encode("lockbox/auth/v1")}, material, 256);
  const key = await crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt,info:info.encode("lockbox/encryption/v1")}, material, {name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);
  return {authKeyB64: b64(new Uint8Array(authBits)), encryptionKey: key};
}
async function api(path, options={}) {
  const headers = {"Content-Type":"application/json", ...(options.headers || {})};
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, {...options, headers});
  const data = await response.json().catch(()=>({detail:"Lỗi máy chủ"}));
  if (!response.ok) throw new Error(data.detail || "Request thất bại");
  return data;
}
function credentials() { const email=$("email").value.trim(), master=$("master").value; if(!email||!master) throw new Error("Nhập email và master password"); return {email,master}; }
async function register() {
  try { const {email,master}=credentials(), salt=crypto.getRandomValues(new Uint8Array(16)), d=await derive(master,salt);
    const out=await api("/api/register",{method:"POST",body:JSON.stringify({email,salt_b64:b64(salt),auth_key_b64:d.authKeyB64})});
    start(out.token,d.encryptionKey); say("Đăng ký thành công. Server chưa từng nhận master password.");
  } catch(e) { say(e.message,true); }
}
async function login() {
  try { const {email,master}=credentials(), s=await api(`/api/auth/salt?email=${encodeURIComponent(email)}`), d=await derive(master,unb64(s.salt_b64));
    const out=await api("/api/login",{method:"POST",body:JSON.stringify({email,auth_key_b64:d.authKeyB64})}); start(out.token,d.encryptionKey); say("Đăng nhập thành công; encryption key chỉ nằm ở tab này.");
  } catch(e) { say(e.message,true); }
}
function start(newToken,key) { token=newToken; encryptionKey=key; localStorage.setItem("lockbox_token",token); $("auth-card").hidden=true; $("app-card").hidden=false; loadItems(); }
async function encrypt(value) { const iv=crypto.getRandomValues(new Uint8Array(12)); const plain=new TextEncoder().encode(JSON.stringify(value)); const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},encryptionKey,plain); return {ciphertext:b64(new Uint8Array(cipher)),iv_b64:b64(iv)}; }
async function decrypt(item) { const raw=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(item.iv_b64)},encryptionKey,unb64(item.ciphertext)); return JSON.parse(new TextDecoder().decode(raw)); }
async function loadItems() {
  if(!encryptionKey) return;
  try { const data=await api("/api/items"), box=$("items"); box.replaceChildren();
    for(const item of data) { const v=await decrypt(item), el=document.createElement("article"); el.className="item";
      const title=document.createElement("strong"); title.textContent=v.site; const p=document.createElement("p"); p.textContent=`${v.username} · ${v.password}`; const note=document.createElement("p"); note.textContent=v.notes || "";
      const edit=document.createElement("button"); edit.textContent="Sửa"; edit.onclick=()=>editItem(item.id,v); const del=document.createElement("button"); del.textContent="Xóa"; del.onclick=()=>removeItem(item.id);
      el.append(title,p,note,edit,document.createTextNode(" "),del); box.append(el);
    } if(!data.length) box.textContent="Vault trống — hãy thêm mục đầu tiên.";
  } catch(e) { say(e.message,true); }
}
function editItem(id,v) { $("item-id").value=id; $("site").value=v.site; $("username").value=v.username; $("item-password").value=v.password; $("notes").value=v.notes || ""; window.scrollTo({top:0,behavior:"smooth"}); }
async function saveItem(e) { e.preventDefault(); try { const id=$("item-id").value, value={site:$("site").value,username:$("username").value,password:$("item-password").value,notes:$("notes").value}; const encrypted=await encrypt(value);
  // Nhãn cố ý chung chung: không để website/username plaintext thành metadata tại server.
  const body={...encrypted,label:"Mục đã mã hóa"}; await api(id?`/api/items/${id}`:"/api/items",{method:id?"PUT":"POST",body:JSON.stringify(body)}); $("item-form").reset(); $("item-id").value=""; await loadItems(); say("Đã mã hóa AES-256-GCM với IV ngẫu nhiên và lưu ciphertext.");
 } catch(e) { say(e.message,true); } }
async function removeItem(id) { if(!confirm("Xóa mục này?"))return; try{await api(`/api/items/${id}`,{method:"DELETE"});loadItems();}catch(e){say(e.message,true)} }
async function show(path) { try { $("output").textContent=JSON.stringify(await api(path),null,2); } catch(e) { say(e.message,true); } }
$("register").onclick=register; $("login").onclick=login; $("item-form").onsubmit=saveItem; $("cancel").onclick=()=>{$("item-form").reset();$("item-id").value=""}; $("refresh").onclick=loadItems; $("leak").onclick=()=>show("/api/demo/db-leak"); $("logs").onclick=()=>show("/api/audit"); $("rotate").onclick=async()=>{try{$("output").textContent=JSON.stringify(await api("/api/kms/rotate",{method:"POST"}),null,2);say("Đã rotate/re-wrap KMS. Tải vault để chứng minh nó vẫn mở được.")}catch(e){say(e.message,true)}};
