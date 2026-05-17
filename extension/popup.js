const policySelect = document.getElementById("policySelect");
const statusText = document.getElementById("statusText");

const DEFAULT_POLICY = "redact";

chrome.storage.local.get(["leaklensPolicy"], function (result) {
  const savedPolicy = result.leaklensPolicy || DEFAULT_POLICY;

  policySelect.value = savedPolicy;
  statusText.textContent = `Current policy: ${savedPolicy}`;
});

policySelect.addEventListener("change", function () {
  const selectedPolicy = policySelect.value;

  chrome.storage.local.set(
    {
      leaklensPolicy: selectedPolicy
    },
    function () {
      statusText.textContent = `Saved policy: ${selectedPolicy}`;
      console.log("[LeakLens popup] Policy saved:", selectedPolicy);
    }
  );
});