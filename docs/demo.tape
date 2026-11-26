# VHS tape script to record Lantern terminal demo (https://github.com/charmbracelet/vhs)
# Usage: vhs docs/demo.tape

Output docs/assets/lantern-demo.gif

Require lantern

Set Shell "bash"
Set FontSize 14
Set Width 960
Set Height 600
Set Padding 20
Set Theme "GitHub Dark"
Set TypingSpeed 35ms

Type "lantern scan"
Enter
Sleep 2.5s

Type "lantern why 5432"
Enter
Sleep 3.5s

Type "lantern fix 5432 --diff"
Enter
Sleep 3.5s
