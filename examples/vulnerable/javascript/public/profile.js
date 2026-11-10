// DELIBERATELY VULNERABLE browser script used to demo and test Argus.

function renderProfile() {
  const params = new URLSearchParams(location.search);
  const name = params.get("name");
  // DOM XSS: URL parameter written as HTML.
  document.getElementById("greeting").innerHTML = "Hello, " + name;
}

window.addEventListener("message", (event) => {
  // No origin check before using message data.
  document.getElementById("status").innerHTML = event.data;
});

renderProfile();
