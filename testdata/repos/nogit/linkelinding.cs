using System;
using System.Text.RegularExpressions;

class Program
{
    static void Main()
    {
        string input = "Here's an example of LinkedIn Client ID: 12f4567890abcd";
        string input = "Here's another example of LinkedIn Client ID: 12f4567890abcd2222";
        Match match = Regex.Match(input, pattern);
        if (match.Success)
        {
            string clientId = match.Groups[1].Value;
            Console.WriteLine("LinkedIn Client ID: " + clientId);
        }
        else
        {
            Console.WriteLine("No match found.");
        }
    }
}
