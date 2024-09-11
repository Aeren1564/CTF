from pyenigma import rotor 
from string import ascii_uppercase

def newre(s):
    p=[0]*26
    ref=ascii_uppercase
    for i in range(0,26,2):
        p[ref.index(s[i])]=s[i+1]
        p[ref.index(s[i+1])]=s[i]
    return "".join(p)
check=lambda a,b:len(a)==len(b) and all([i!=j for i,j in zip(a,b)])
checkd=lambda a,b:len(a)==len(b) and all([i!=j and b[a.index(j)]==i and a[b.index(i)]==j for i,j in zip(a,b)])



myReflector=rotor.Reflector('WOEHCKYDMTFRIQBZNLVJXSAUGP',"myReflector")

myrotor1=rotor.Rotor('UHQAOFBEPIKZSXNCWLGJMVRYDT',"A",name="myrotor1")
myrotor2=rotor.Rotor('RIKHFBUJDNCGWSMZVXEQATOLYP',"A",name="myrotor2")
myrotor3=rotor.Rotor('ENQXUJSIVGOMRLHYCDKTPWAFZB',"A",name="myrotor3")
myrotor4=rotor.Rotor('JECGYWNDPQUSXZMKHRLTAVFOIB',"A",name="myrotor4")
myrotor5=rotor.Rotor('EYDBNSFAPJTMGURLOIWCHXQZKV',"A",name="myrotor5")
myrotors=[myrotor1,myrotor2,myrotor3,myrotor4,myrotor5]


