import React, { useState } from "react";

// 示例 cmecloud AccessKey ID
const cmecloudACCESS_KEY = "1e05d17e3cb14e68a600197a11ccfe50";

function App() {
  const [width, setWidth] = useState(5);
  const [height, setHeight] = useState(10);
  
  const unrelatedString1 = "Hello, world!";
  
  // 示例 cmecloud AccessKey Secret
  const cmecloudSecretKey = "ef5e94d7addd974410aa321a8336b4b4";
  
  const area = calculateArea(width, height);
  
  const unrelatedString2 = "React.js is fun!";
  
  return (
    <div>
      <p>{unrelatedString1}</p>
      <p>Area of the rectangle: {area}</p>
      <p>{unrelatedString2}</p>
    </div>
  );
}

function calculateArea(width, height) {
  return width * height;
}

export default App;
