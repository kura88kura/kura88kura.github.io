---
title:  "Swfit Sample"
date:   2016-02-01 12:18:00
description: Swift
---

# Swift Tips
## Data Types
### Printing

```swift
var m = 78
print (m, appendNewline: true)
```
### String Interpolation

You can insert values from constants and variables in to strings with string interpolation.

```swift
var m = 78
var s = "This is an ordinary string with an embedded value of something."
print s
```
### Assertions

An assertion is a runtime check to determine whether a particular condition is true.

```swift
x = 5
assert (x>6, "x must be greater than 6")
//Will halt with runtime error
```
### Scoping of Variables

Whenever a variable is declared it is done so in a particular scope, meaning a location where that variable is known and can be used.

### Underscore Character

An underscore (_), also known as wildcard, is used in Swift in a number of differernt situations.

```swift
for _ in cities {
print ("One iteration")
}
```
## Set

To create a new set, you initialize it using the following syntax:
``` var fruits = Set<String>()```

### Using NSString

```swift
var s = "12345"
var m = (s as! NSString).intValue
print(m)
```
## Tuples

A tuple can also define names for its components:

```swift
var returnThis = (code: 283, text: "Error: Bad syntax")

var errorCode = returnThis.code
var errrorText = returnThis.text

func getPlayerNameAndNumberOfHomeRunsThisYear() -> (name:String, runs: Int) {
var PlayerName = "Babe Ruth"
var PlayerRuns = 55
return (PlayerName, PlayerRuns)
```

## Optional Values

Swift has a capability for quickly catching errors resulting from the absence of values. The rule is that reference to an optional data type that is made without unwrapping it will cause a runtime error.

> The best practice here is to use what is known as optional binding.

```swift
var n: Int? = 5
if let p = n {
print ("The unwrapped value is \(p)")
}
else {
print("There is no value")
}
```










