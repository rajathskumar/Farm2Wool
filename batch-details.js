/* One canonical batch format for every portal and every QR image. */
(function () {
'use strict';
const parameters = [
 ['Fibre Thickness','fibreThickness'],['Fibre Length','fibreLength'],['Moisture','moisture'],
 ['Cleanliness','cleanliness'],['Grease / Lanolin','grease'],['Wool Yield','woolYield','yield'],
 ['Fibre Strength','fibreStrength','strength'],['Colour','colour'],
 ['Fibre Uniformity','fibreUniformity','uniformity'],['Crimp','crimp'],
 ['Contamination','contamination'],['Odour / Storage','odourStorage'],['Pest / Damage','pestDamage'],
 ['Wool Type','woolType'],['Shearing Condition','shearingCondition'],['Lot Consistency','lotConsistency']
];
const display = value => value === undefined || value === null || value === '' ? 'Not recorded' : String(value);
window.f2wBatchRows = function(batch, full=true) {
 const quality = batch.qualityReport?.qualityPercentage ?? batch.qualityScore;
 const q = batch.qualityParameters || {};
 const rows = [['Batch ID',batch.id],['Name',batch.batchName],['Location',batch.location],
  ['Breed',batch.breed],['Weight',batch.weight == null ? null : batch.weight+' kg'],
  ['Status',batch.purchaseStatus || 'Available'],['Quality',quality == null ? null : quality+'%']];
 if(full) {
  rows.push(['Inspection',batch.inspectionStatus || 'Not Started']);
  parameters.forEach(([label,key,alias]) => rows.push([label,q[key] ?? (alias ? q[alias] : undefined)]));
 }
 return rows.map(([label,value])=>[label,display(value)]);
};
window.f2wQRText = function(batch) {
 const rows=f2wBatchRows(batch);
 return ['BATCH DETAILS',...rows.slice(0,8).map(([label,value])=>label+': '+value),
  '16 QUALITY PARAMETERS',...rows.slice(8).map(([label,value])=>label+': '+value)].join('\n');
};
window.f2wQRUrl = function(batch) {
 return 'https://api.qrserver.com/v1/create-qr-code/?size=600x600&margin=24&data='+encodeURIComponent(f2wQRText(batch));
};
window.f2wShowBatch = function(id,full=true) {
 const batch=getBatches().find(item=>item.id===id);
 if(!batch)return;
 document.getElementById('f2w-batch-dialog')?.remove();
 const dialog=document.createElement('dialog');dialog.id='f2w-batch-dialog';dialog.className='f2w-batch-dialog';
 const header=document.createElement('header');header.className='f2w-batch-header';
 const title=document.createElement('h2');title.textContent='BATCH DETAILS';
 const close=document.createElement('button');close.type='button';close.textContent='×';close.setAttribute('aria-label','Close batch details');
 header.append(title,close);
 const body=document.createElement('div');body.className='f2w-batch-body';
 const grid=document.createElement('div');grid.className='f2w-batch-grid';
 f2wBatchRows(batch,full).forEach(([label,value],index)=>{
  if(full && index===8){const heading=document.createElement('h3');heading.textContent='16 QUALITY PARAMETERS';heading.className='f2w-batch-section';grid.append(heading);}
  const box=document.createElement('div');box.className='f2w-batch-field';
  const caption=document.createElement('span');caption.textContent=label;
  const text=document.createElement('strong');text.textContent=value;box.append(caption,text);grid.append(box);
 });
 body.append(grid);
 if(full){
  const qr=document.createElement('section');qr.className='f2w-batch-qr';
  const img=document.createElement('img');img.width=300;img.height=300;img.alt='Scan to read the complete batch details';img.src=f2wQRUrl(batch);
  const note=document.createElement('p');note.textContent='Scan for the labeled batch details and all 16 quality parameters.';
  img.onerror=()=>{img.hidden=true;note.textContent='QR image unavailable. Check your internet connection. All details remain visible above.';};
  qr.append(img,note);body.append(qr);
 }
 dialog.append(header,body);document.body.append(dialog);
 const dismiss=()=>{dialog.close();dialog.remove();};close.onclick=dismiss;
 dialog.addEventListener('close',()=>dialog.remove());
 dialog.addEventListener('click',event=>{if(event.target===dialog){const r=dialog.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)dismiss();}});
 dialog.showModal();dialog.scrollTop=0;
};
})();
