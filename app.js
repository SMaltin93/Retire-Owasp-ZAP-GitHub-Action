// Update the message in the 'message' <p> element
document.getElementById('message').textContent = 'Hello, World! from our bad commit agian';

// create a button element
const button = document.createElement('button');
button.textContent = 'Click me!';
button.addEventListener('click', () => {
  alert('Nice job! You clicked the button!');
});