const accessTokens = [
    'facebook0 = 43b95fc3730122fc3d3fc5e2f5b5e5d7',
    'facebook1:= 508cfb13d6785a6f31b6d66c24d1e9b8',
    'facebook_fake:= ssssssssssssssssssssssssssssssss',
    'facebook_fake:= sssd232541ssssss44sssssddddddsss',
    'facebook-2 =\'f7cdd0d6c8ab6e680dc6afcf43cfa88b\''
];

const pattern = /(?i)(?:facebook)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)/;

accessTokens.forEach((token, i) => {
    if (pattern.test(token)) {
        console.log(`Matched Access Token ${i}: ${token}`);
    } else {
        console.log(`No match for Access Token ${i}: ${token}`);
    }
});
