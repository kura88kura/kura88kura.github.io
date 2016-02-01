---
title:  "Ruby Tricks"
date:   2016-02-01 14:18:00
description: Ruby
---

# Ruby Tricks

## Create a hash from a list of values

```ruby
Hash['key1', 'value1', 'key2', 'value2']

# => {"key1"=>"value1", "key2"=>"value2"]
```

## Lambda Literal `->`

```ruby
a = -> (v) {v+1}
a.call(2)
# => 3
```

## Double Pipe Equals `||=`

```ruby
def total
  @total ||= (1..1000).to_a.inject(:+)
end
```

## Generate array of alphabet

```ruby
('a'..'e').to_a

# => ["a", "b", "c", "d", "e"]
```

## Generate random characters mixed with numbers

```ruby
[*('a'..'z'),*('A'..'Z'),*('0'..'9')].shuffle[0,9].join
# => 4vu2txmhn
```

