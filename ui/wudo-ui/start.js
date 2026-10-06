import init from '/wudo_ui.js';
init().catch(() => {
  document.getElementById('status').textContent = 'Enrollment could not load. Contact your administrator.';
});
