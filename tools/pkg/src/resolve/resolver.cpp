#include "resolve/resolver.hpp"

#include <algorithm>
#include <deque>
#include <unordered_set>
#include <utility>

namespace duet::resolve
{

std::unordered_map<std::string, ResolvedPackage> BuildIndex(
    const std::vector<std::pair<std::string, repo::RepoManifest>>& repos)
{
    std::unordered_map<std::string, ResolvedPackage> out;
    for (const auto& [repo_name, manifest] : repos)
    {
        for (const auto& pkg : manifest.packages)
        {
            // First-write-wins matches the contract documented in
            // resolver.hpp — earlier repos take priority over later
            // ones for duplicate package names.
            out.emplace(pkg.name, ResolvedPackage{repo_name, pkg});
        }
    }
    return out;
}

Expected<std::vector<ResolvedPackage>> ResolveAgainstIndex(
    std::string_view target, const std::unordered_map<std::string, ResolvedPackage>& index)
{
    // Discover the closure of packages reachable from `target`
    // via deps, plus the dep edges (for the topo sort).
    std::unordered_map<std::string, std::vector<std::string>> deps;
    std::unordered_set<std::string> seen;
    std::deque<std::string> queue;

    const std::string target_str{target};
    if (index.find(target_str) == index.end())
    {
        return std::unexpected(MakeError(ErrorCode::PackageNotFound, "no repo provides package: " + target_str));
    }
    queue.push_back(target_str);
    seen.insert(target_str);

    while (!queue.empty())
    {
        const std::string name = std::move(queue.front());
        queue.pop_front();
        auto it = index.find(name);
        if (it == index.end())
        {
            return std::unexpected(MakeError(ErrorCode::PackageNotFound, "dependency not found in any repo: " + name));
        }
        std::vector<std::string> these_deps;
        these_deps.reserve(it->second.entry.deps.size());
        for (const auto& d : it->second.entry.deps)
        {
            these_deps.push_back(d);
            if (seen.insert(d).second)
                queue.push_back(d);
        }
        deps.emplace(name, std::move(these_deps));
    }

    // Build incoming-edge counts. Kahn's algorithm: start nodes
    // are those with 0 incoming edges.
    std::unordered_map<std::string, std::vector<std::string>> rev_adj;
    std::unordered_map<std::string, std::size_t> in_degree;
    for (const auto& [name, _] : deps)
        in_degree[name] = 0;
    for (const auto& [name, dlist] : deps)
    {
        for (const auto& d : dlist)
        {
            rev_adj[d].push_back(name); // edge d -> name (d is a dependency of name)
            in_degree[name]++;
        }
    }

    // Kahn: process zero-indegree nodes, push their dependents
    // once everything they depend on has been emitted. We want
    // deps-first order so we walk forward edges (rev_adj keyed
    // on dependency → dependents).
    std::deque<std::string> ready;
    for (const auto& [name, deg] : in_degree)
    {
        if (deg == 0)
            ready.push_back(name);
    }
    // Stable order: sort the initial frontier. Otherwise the
    // unordered_map iteration order would make output flaky
    // between runs.
    std::sort(ready.begin(), ready.end());

    std::vector<ResolvedPackage> out;
    out.reserve(in_degree.size());
    std::size_t emitted = 0;
    while (!ready.empty())
    {
        const std::string node = std::move(ready.front());
        ready.pop_front();
        auto idx_it = index.find(node);
        // Already checked above.
        out.push_back(idx_it->second);
        ++emitted;
        auto adj_it = rev_adj.find(node);
        if (adj_it == rev_adj.end())
            continue;
        // Stable order on the dependent group as well.
        std::vector<std::string> dependents = adj_it->second;
        std::sort(dependents.begin(), dependents.end());
        for (const auto& dependent : dependents)
        {
            auto& deg = in_degree[dependent];
            --deg;
            if (deg == 0)
                ready.push_back(dependent);
        }
    }

    if (emitted != in_degree.size())
    {
        // Cycle: at least one node still has in_degree > 0.
        std::string detail;
        for (const auto& [name, deg] : in_degree)
        {
            if (deg > 0)
            {
                if (!detail.empty())
                    detail += ", ";
                detail += name;
            }
        }
        return std::unexpected(MakeError(ErrorCode::DependencyCycle,
                                         "dependency cycle detected involving target: " + target_str,
                                         "still-pending: " + detail));
    }
    return out;
}

Expected<std::vector<ResolvedPackage>> Resolve(std::string_view target,
                                               const std::vector<std::pair<std::string, repo::RepoManifest>>& repos)
{
    return ResolveAgainstIndex(target, BuildIndex(repos));
}

} // namespace duet::resolve
