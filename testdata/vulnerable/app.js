function render(element, userContent) {
  element.innerHTML = userContent;
}

function evaluateRequest(userExpression) {
  return eval(userExpression);
}
