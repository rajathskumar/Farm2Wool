/* Account UI. Credentials and sessions are managed by server.py, never localStorage. */
(() => {
'use strict';
const pages = {farmer:'farmer.html', manufacturer:'manufacture.html', customer:'customer.html'};
const roles = Object.keys(pages);
const label = role => role[0].toUpperCase() + role.slice(1);
async function request(path, data) {
  const response = await fetch(path, {method:data === undefined ? 'GET':'POST', credentials:'same-origin',
    headers:data === undefined ? {} : {'Content-Type':'application/json', 'X-F2W-Request':'1'},
    body:data === undefined ? undefined : JSON.stringify(data), cache:'no-store'});
  const result = await response.json();
  if(!response.ok) throw new Error(result.error || 'Please log in again.');
  return result;
}
const form = document.getElementById('authForm');
if(form) {
  const params = new URLSearchParams(location.search);
  const role = document.getElementById('role');
  role.value = roles.includes(params.get('role')) ? params.get('role') : 'farmer';
  let mode = params.get('mode') === 'signup' ? 'signup':'login';
  let busy = false;
  const submit = document.getElementById('authSubmit');
  const error = document.getElementById('authError');
  const password = document.getElementById('password');
  const confirmation = document.getElementById('confirmPassword');
  function render() {
    const signup = mode === 'signup';
    document.body.dataset.role = role.value;
    document.getElementById('portalLabel').textContent = label(role.value) + ' portal';
    document.getElementById('authHeading').textContent = signup ? 'Create your account':'Welcome back';
    document.getElementById('authDescription').textContent = signup ? 'A few details to get you started.':'Log in with your mobile number and password.';
    document.querySelectorAll('.f2w-new-fields').forEach(section => {
      section.hidden = !signup;
      section.querySelectorAll('input').forEach(input => {input.disabled=!signup; input.required=signup && input.id!=='business';});
    });
    const business = document.getElementById('business');
    const showBusiness = signup && role.value === 'manufacturer';
    document.getElementById('businessField').hidden = !showBusiness;
    business.disabled = !showBusiness;
    password.autocomplete = signup ? 'new-password':'current-password';
    password.minLength = signup ? 10:1;
    document.getElementById('loginTab').setAttribute('aria-pressed', String(!signup));
    document.getElementById('signupTab').setAttribute('aria-pressed', String(signup));
    submit.textContent = signup ? 'Create account →':'Login →';
    error.hidden = true;
    confirmation.setCustomValidity('');
    const url = new URL(location.href);url.searchParams.set('role',role.value);url.searchParams.set('mode',mode);
    history.replaceState(null,'',url);
  }
  document.getElementById('loginTab').onclick = () => {if(!busy){mode='login';password.value='';confirmation.value='';render();}};
  document.getElementById('signupTab').onclick = () => {if(!busy){mode='signup';password.value='';render();}};
  role.onchange = () => {password.value='';confirmation.value='';render();};
  confirmation.oninput = () => confirmation.setCustomValidity('');
  password.oninput = () => confirmation.setCustomValidity('');
  document.getElementById('togglePassword').onclick = event => {
    const show = password.type === 'password';password.type = show ? 'text':'password';
    event.currentTarget.textContent = show ? 'Hide':'Show';
    event.currentTarget.setAttribute('aria-label',show ? 'Hide password':'Show password');
    event.currentTarget.setAttribute('aria-pressed',String(show));
  };
  form.onsubmit = async event => {
    event.preventDefault();if(busy)return;
    error.hidden=true;
    if(mode==='signup' && password.value!==confirmation.value){confirmation.setCustomValidity('Passwords do not match.');confirmation.reportValidity();return;}
    if(!form.reportValidity())return;
    const payload = Object.fromEntries(new FormData(form));payload.role=role.value;
    busy=true;submit.disabled=true;role.disabled=true;
    document.getElementById('loginTab').disabled=true;document.getElementById('signupTab').disabled=true;
    submit.textContent=mode==='signup'?'Creating account…':'Logging in…';
    try {
      const result=await request('/api/'+(mode==='signup'?'signup':'login'),payload);
      // Destination is selected locally from known portal paths.
      if(result.ok)location.assign('/'+pages[payload.role]);
    } catch(reason) {
      error.textContent=reason instanceof TypeError ? 'Could not reach the account server. Start server.py and open the localhost address.':reason.message;
      error.hidden=false;error.focus();
    } finally {
      busy=false;submit.disabled=false;role.disabled=false;
      document.getElementById('loginTab').disabled=false;document.getElementById('signupTab').disabled=false;
      submit.textContent=mode==='signup'?'Create account →':'Login →';
    }
  };
  render();
  const notice=document.getElementById('authNotice');
  if(params.has('switch')){notice.hidden=false;notice.textContent='This portal needs its own account. Log in here, or select your current portal.';}
  if(params.has('logout')){notice.hidden=false;notice.textContent='You have been logged out.';}
} else {
  const page=location.pathname.split('/').pop() || 'index.html';
  const role=roles.find(key=>pages[key]===page);
  if(role){
    if(location.protocol==='file:'){
      document.body.replaceChildren();
      const note=document.createElement('p');note.textContent='Start server.py and open http://localhost:8000 to log in. Accounts require the Farm2Wool server.';document.body.append(note);return;
    }
    request('/api/me').then(({user})=>{
      if(!user || user.role!==role){location.replace('/login.html?role='+role);return;}
      const bar=document.createElement('div');bar.className='f2w-account-bar';bar.setAttribute('aria-label','Your account');
      const text=document.createElement('span');text.textContent=user.name+' · '+label(user.role);
      const button=document.createElement('button');button.type='button';button.textContent='Logout';
      const status=document.createElement('span');status.setAttribute('role','status');
      button.onclick=async()=>{button.disabled=true;try{await request('/api/logout',{});location.replace('/login.html?role='+role+'&logout=1');}catch(e){status.textContent='Logout failed. Please try again.';button.disabled=false;}};
      bar.append(text,button,status);document.body.prepend(bar);
    }).catch(()=>location.replace('/login.html?role='+role));
    // Recheck after Back restores a page from the browser's back-forward cache.
    window.addEventListener('pageshow', event=>{if(event.persisted)location.reload();});
  }
}
})();
