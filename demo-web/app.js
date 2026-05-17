const chatForm = document.getElementById("chatForm");
const messageInput = document.getElementById("messageInput");
const chatHistory = document.getElementById("chatHistory");

function addMessage(text, type) {
  const messageElement = document.createElement("div");

  messageElement.classList.add("message");

  if (type === "user") {
    messageElement.classList.add("user-message");
  } else {
    messageElement.classList.add("system-message");
  }

  messageElement.textContent = text;
  chatHistory.appendChild(messageElement);
  chatHistory.scrollTop = chatHistory.scrollHeight;
}

chatForm.addEventListener("submit", function (event) {
  event.preventDefault();

  const messageText = messageInput.value.trim();

  if (!messageText) {
    return;
  }

  addMessage(messageText, "user");

  messageInput.value = "";
  messageInput.focus();
});

const fileInput = document.getElementById("fileInput");
const selectedFileName = document.getElementById("selectedFileName");

fileInput.addEventListener("change", function () {
  const selectedFile = fileInput.files[0];

  if (!selectedFile) {
    selectedFileName.textContent = "No file selected";
    return;
  }

  selectedFileName.textContent = selectedFile.name;
});