# Plan operators

The operator vocabulary of a [query plan](/guide/query-plans)'s `condition` tree: Cerbos' own set, plus two Kerberos extensions.

`condition` is a tree of `{ expression: { operator, operands } }` / `{ variable }` / `{ value }` operands. Variables are Cerbos-named: `request.resource.id` and `request.resource.attr.<path>`.

| Operators | Meaning |
| --------- | ------- |
| `and`, `or`, `not` | Boolean composition. |
| `eq`, `ne`, `lt`, `le`, `gt`, `ge` | Comparisons (`===`, `!==`, `<`, `<=`, `>`, `>=`). |
| `in` | List membership (`list.includes(x)`). |
| `add`, `sub`, `mult`, `div`, `mod` | Arithmetic (`+`, `-`, `*`, `/`, `%`). |
| `index`, `list` | Computed member access, list literals. |
| `opaque` **(Kerberos)** | Statically unplannable condition — [post-filter](/guide/query-plans#opaque-conditions-post-filtering). |
| `relation` **(Kerberos)** | ReBAC dependency — [expand or post-check](/guide/query-plans#relation-operands-rebac). |
