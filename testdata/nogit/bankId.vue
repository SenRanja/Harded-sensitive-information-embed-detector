<template>
  <div>
     <h1>Welcome to my page</h1>
      <nav>
        <ul>
          <li><a href="#">Home</a></li>
          <li><a href="#">About</a></li>
          <li><a href="#">Contact</a></li>
        </ul>
      </nav>
  </div>
</template>

<script>
export default {
  data() {
    return {
      bankid: '6222025642650232529',
      FakeBankid: '6322025642650562529',
      FakeBankid2: '6422025642650642529',
    };
  },
  // 组件其他代码
};
</script>

<style>
body {
  font-family: Arial, sans-serif;
  margin: 0;
  padding: 0;
}

header {
  background-color: #333;
  color: #fff;
  padding: 20px;
}

nav ul {
  margin: 0;
  padding: 0;
  list-style: none;
}

nav li {
  display: inline-block;
  margin-right: 20px;
}

nav a {
  color: #fff;
  text-decoration: none;
}

main {
  margin: 20px;
}

h1, h2 {
  font-weight: normal;
}

h1 {
  font-size: 36px;
}

h2 {
  font-size: 24px;
  margin-top: 40px;
}

ul {
  margin: 0;
  padding: 0;
  list-style: none;
}

li {
  margin-bottom: 10px;
}

a {
  color: #333;
  text-decoration: none;
}
</style>
