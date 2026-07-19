import javascript

predicate isTargetCall(
  API::CallNode call,
  string packageName,
  string apiName
) {
  (
    packageName = "lodash" and
    (
      (
        call = API::moduleImport("lodash").getACall() and
        apiName = "<module>"
      )
      or
      exists(string member |
        call = API::moduleImport("lodash").getMember(member).getACall() and
        apiName = member
      )
    )
  )
  or
(
    packageName = "minimist" and
    (
      (
        call = API::moduleImport("minimist").getACall() and
        apiName = "<module>"
      )
      or
      exists(string member |
        call = API::moduleImport("minimist").getMember(member).getACall() and
        apiName = member
      )
    )
  )
  or
(
    packageName = "debug" and
    (
      (
        call = API::moduleImport("debug").getACall() and
        apiName = "<module>"
      )
      or
      exists(string member |
        call = API::moduleImport("debug").getMember(member).getACall() and
        apiName = member
      )
    )
  )
  or
(
    packageName = "ms" and
    (
      (
        call = API::moduleImport("ms").getACall() and
        apiName = "<module>"
      )
      or
      exists(string member |
        call = API::moduleImport("ms").getMember(member).getACall() and
        apiName = member
      )
    )
  )
}

from API::CallNode call, string packageName, string apiName
where isTargetCall(call, packageName, apiName)
select
  packageName,
  apiName,
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.getLocation().getStartColumn()