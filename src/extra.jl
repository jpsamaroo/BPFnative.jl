### Extra utility methods

Host.hostmap(obj::API.Object, map::RT.RTMap{Name,MT,K,V,ME,F}) where {Name,MT,K,V,ME,F} =
    Host.hostmap(API.findmap(obj, String(Name)); K=K, V=V)
