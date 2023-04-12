public class Example {

    // 示例 JingDong Cloud AccessKey ID
    private static final String jdcloud_ACCESS_KEY = "1e05d17e3cb14e68a600197a11ccfe50";

    public static void main(String[] args) {
        String unrelatedString1 = "Hello, world!";
        System.out.println(unrelatedString1);
        
        // 示例 JingDong Cloud AccessKey Secret
        String jdcloudSecretKey = "ef5e94d7addd974410aa321a8336b4b4";
        
        int width = 5;
        int height = 10;
        int area = calculateArea(width, height);
        System.out.println("Area of the rectangle: " + area);
        
        String unrelatedString2 = "Java is fun!";
        System.out.println(unrelatedString2);
    }

    public static int calculateArea(int width, int height) {
        return width * height;
    }
}
