from tkinter import *
from graphics import *
from scapy.all import *
from collections import Counter

root = Tk()

# width X hight format
root.geometry("720x540")
# width , hight format
root.minsize(540,360)

root.maxsize(1920,1080)

# for title
root.title("Flood Attack Detection Tool")

#important labels
# text - add text
# bg - background color i.e. bd("red")
# fg - foreground ( text color )
# font - set the font e.g. font("_fontname_", font size , "bold"/"italic" )
# padx - x padding
# pady - y padding
# relief - border styling - SUNKEN , RAISED , GROOVE , RIDGE
# borderwidth = size
message = Label(root,text = "This is a GUI for flood attack detection ",bg = "skyblue", font="comicsansms 20 bold" , borderwidth=4 , relief = RAISED)
message.pack()

f3 = Frame(root,bg="grey",borderwidth=4)
f3.pack(side=TOP, fill="x")

f1 = Frame(root,bg = "green", borderwidth=4)
f1.pack(side=LEFT)

f2 = Frame(root,bg="yellow",borderwidth=4)
f2.pack(side=RIGHT)



message = Label(f1,text = "Button",bg = "skyblue", font="comicsansms 20 bold" , borderwidth=4 , relief = RAISED)
message.pack()

message = Label(f2,text = "Message",bg = "skyblue", font="comicsansms 20 bold" , borderwidth=4 , relief = RAISED)
message.pack()

message = Label(f3,text = "Graph",bg = "skyblue", font="comicsansms 20 bold" , borderwidth=4 , relief = RAISED)
message.pack()

#w = Text(root, width = 50 , height = 10 , bg = "light blue")
#w.pack()


# makegraph()

def main():
    net_pack = sniff(filter="host 192.168.43.124", timeout=10)
    wrpcap("file.pcap", net_pack)
    # filename = str(input("What is the name of the file? "))

    # sets packet source IPAs to sources, sourcenum also has # of occurrences
    IP.payload_guess = []
    #sources is list //// sourcenum is dictionary
    sources = list((p[IP].src) for p in PcapReader("file.pcap") if IP in p)
    sourcenum = collections.Counter(sources)
    print(sourcenum)
    

    tex = ""
    count = 0
    for x in sourcenum:
        freq = sourcenum[x]
        if (x != "192.168.43.124"):
            if(freq>10):
                count = count + 1
                #Output.insert("IP:",x)
                #Output.insert("No. OF PACKETS:",freq)
                #w.insert(END,"ALERT:FLOOD ATTACK DETECTED")
                tex = "ALERT:FLOOD ATTACK DETECTED"
                label.config(text=tex)
                break
            else:
                continue

    if ( count == 0):
       # w.insert(END,"::your system is safe::")  \
       tex = " YOUR SYSTEM IS SAFE"
       label.config(text=tex)

    makegraph()
    
label = Label(f2,text = "",bg = "skyblue", font="comicsansms 20 bold" , borderwidth=4)
label.pack()

def makegraph():
    
    sources = list((p[IP].src) for p in PcapReader("file.pcap") if IP in p)
    sourcenum = collections.Counter(sources)
    howmany = sum(1 for x in sourcenum.values())
    width = 1000 / howmany

    # creates graph window with white background
    win = GraphWin("Packets Sent From Certain Addresses", 1080, 360)
    win.setBackground("white")
    #x axis
    Line(Point(80, 330), Point(1080, 330)).draw(win)
    #y axis
    Line(Point(80, 0), Point(80, 330)).draw(win)

    # creates y axis labels
    Text(Point(40, 330), " 0k pkts").draw(win)
    Text(Point(40, 280), " 3k pkts").draw(win)
    Text(Point(40, 230), " 6k pkts").draw(win)
    Text(Point(40, 180), " 9k pkts").draw(win)
    Text(Point(40, 130), " 12k pkts").draw(win)
    Text(Point(40, 80), " 15k pkts").draw(win)
    Text(Point(40, 30), " 18k+ pkts").draw(win)

    # create text and bar for each IPA
    a = 80
    subaddr = 1
    for ipa in sourcenum:
        whooheight = sourcenum.get(str(ipa))
        hooheight = whooheight / (18000 / 292)
        hoheight = 330 - hooheight
        print(hoheight)

        if hoheight >= 30:
            hoopyheight = hoheight
        else:
            hoopyheight = 30

        bar = Rectangle(Point(a, 330), Point(a + width, hoopyheight))
        bar.setFill("blue")
        bar.draw(win)
        Text(Point(a + width / 2, 345), ipa).draw(win)
        Text(Point(a + width / 2, hoopyheight - 15), str(whooheight) + " packets").draw(win)
        a += width

    input("Press <Enter> to quit")
    win.close()




# button

b1 = Button(f1,bg="blue",fg="white",text="SCAN",command=main
    , borderwidth=4 , relief=RAISED)
b1.pack(side=LEFT)

b2 = Button(f1,bg="blue",fg="white",text="GRAPH",command = makegraph,borderwidth=4 , relief=RAISED)
b2.pack(side=LEFT)



# main loop for calling functions
root.mainloop()
