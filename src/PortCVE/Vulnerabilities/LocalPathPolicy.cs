using System.Runtime.InteropServices;

namespace PortCVE.Vulnerabilities;

internal sealed record LocalPathValidation(
    bool IsValid,
    string? FullPath,
    string Code,
    string Message);

internal static class LocalPathPolicy
{
    private const uint InvalidFileAttributes = uint.MaxValue;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

    public static LocalPathValidation ValidateLocalDirectoryPath(string path)
    {
        var resolved = Resolve(path, "local_path");
        if (!resolved.IsValid)
        {
            return resolved;
        }

        var fullPath = resolved.FullPath!;
        var root = Path.GetPathRoot(fullPath)!;
        var inspection = InspectComponents(fullPath, root, allowMissingTail: true, "local_path");
        if (!inspection.IsValid)
        {
            return Invalid(inspection.Code!, inspection.Message!);
        }

        if (inspection.FinalExists && !IsDirectory(inspection.FinalAttributes))
        {
            return Invalid("local_path_invalid", "The local directory path names an existing non-directory.");
        }

        return new(true, fullPath, "ok", "The directory path is local.");
    }

    public static LocalPathValidation ValidateExistingLocalFile(string path)
    {
        return ValidateLocalFile(path, requireExists: true, "sbom_path", "SBOM");
    }

    public static LocalPathValidation ValidateOptionalLocalFile(string path)
    {
        return ValidateLocalFile(path, requireExists: false, "sbom_path", "SBOM");
    }

    public static LocalPathValidation ValidateExistingImportFile(string path)
    {
        return ValidateLocalFile(path, requireExists: true, "import_path", "Import input");
    }

    public static LocalPathValidation ValidateOptionalImportOutputFile(string path)
    {
        return ValidateLocalFile(path, requireExists: false, "import_output_path", "Import output");
    }

    public static LocalPathValidation ValidateOptionalRemoteOutputFile(string path)
    {
        return ValidateLocalFile(path, requireExists: false, "remote_output_path", "Remote report output");
    }

    private static LocalPathValidation ValidateLocalFile(
        string path,
        bool requireExists,
        string codePrefix,
        string displayName)
    {
        var resolved = Resolve(path, codePrefix);
        if (!resolved.IsValid)
        {
            return resolved;
        }

        var fullPath = resolved.FullPath!;
        var root = Path.GetPathRoot(fullPath)!;
        var inspection = InspectComponents(fullPath, root, allowMissingTail: !requireExists, codePrefix);
        if (!inspection.IsValid)
        {
            return inspection.IsMissing && requireExists
                ? Invalid($"{codePrefix}_not_found", $"{displayName} file not found: '{fullPath}'.")
                : Invalid(inspection.Code!, inspection.Message!);
        }

        if (inspection.FinalExists && IsDirectory(inspection.FinalAttributes))
        {
            return Invalid($"{codePrefix}_invalid", $"The {displayName.ToLowerInvariant()} path must name a regular file, not a directory.");
        }

        return new(true, fullPath, "ok", "The path is a local regular file.");
    }

    internal static bool IsAllowedLocalDriveType(DriveType driveType) => driveType is
        DriveType.Fixed or DriveType.Removable or DriveType.CDRom or DriveType.Ram;

    internal static bool IsReparsePoint(FileAttributes attributes) =>
        (attributes & FileAttributes.ReparsePoint) != 0;

    internal static bool TryGetAttributesWithoutFollowing(
        string path,
        out FileAttributes attributes,
        out int errorCode)
    {
        var raw = GetFileAttributesW(path);
        if (raw == InvalidFileAttributes)
        {
            attributes = default;
            errorCode = Marshal.GetLastWin32Error();
            return false;
        }

        attributes = (FileAttributes)raw;
        errorCode = 0;
        return true;
    }

    private static LocalPathValidation Resolve(string path, string codePrefix)
    {
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return Invalid($"{codePrefix}_invalid", $"The path is invalid: {exception.Message}");
        }

        if (fullPath.StartsWith("\\\\", StringComparison.Ordinal))
        {
            return Invalid($"{codePrefix}_network", "The path must not be a UNC or device path.");
        }

        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            return Invalid($"{codePrefix}_invalid", "The path has no local drive root.");
        }

        try
        {
            var driveType = new DriveInfo(root).DriveType;
            if (!IsAllowedLocalDriveType(driveType))
            {
                return Invalid($"{codePrefix}_network",
                    $"The path must be on a local drive; drive type '{driveType}' is not allowed.");
            }
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return Invalid($"{codePrefix}_invalid", $"The path drive could not be validated: {exception.Message}");
        }

        return new(true, fullPath, "ok", "The path has a permitted local drive root.");
    }

    private static ComponentInspection InspectComponents(
        string fullPath,
        string root,
        bool allowMissingTail,
        string codePrefix)
    {
        var finalAttributes = default(FileAttributes);
        var missingTail = false;

        foreach (var component in LexicalPathComponents(fullPath, root))
        {
            if (missingTail)
            {
                continue;
            }

            if (!TryGetAttributesWithoutFollowing(component, out var attributes, out var errorCode))
            {
                if (errorCode is ErrorFileNotFound or ErrorPathNotFound)
                {
                    if (!allowMissingTail)
                    {
                        return ComponentInspection.Missing();
                    }

                    missingTail = true;
                    continue;
                }

                return ComponentInspection.Invalid(
                    $"{codePrefix}_invalid",
                    $"The local path component '{component}' could not be inspected (Windows error {errorCode}).");
            }

            // GetFileAttributesW reports the attributes of the named reparse point itself.
            // Inspecting from the root down means no child beneath it is ever resolved first.
            if (IsReparsePoint(attributes))
            {
                return ComponentInspection.Invalid(
                    $"{codePrefix}_reparse",
                    "The path must not traverse a symbolic link, junction, mount point, or cloud placeholder.");
            }

            finalAttributes = attributes;
        }

        return ComponentInspection.Valid(!missingTail, finalAttributes);
    }

    private static IEnumerable<string> LexicalPathComponents(string fullPath, string root)
    {
        var current = root;
        yield return current;
        var relative = Path.GetRelativePath(root, fullPath);
        foreach (var component in relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            yield return current;
        }
    }

    private static bool IsDirectory(FileAttributes attributes) =>
        (attributes & FileAttributes.Directory) != 0;

    private static LocalPathValidation Invalid(string code, string message) =>
        new(false, null, code, message);

    private sealed record ComponentInspection(
        bool IsValid,
        bool IsMissing,
        bool FinalExists,
        FileAttributes FinalAttributes,
        string? Code,
        string? Message)
    {
        public static ComponentInspection Valid(bool finalExists, FileAttributes finalAttributes) =>
            new(true, false, finalExists, finalAttributes, null, null);

        public static ComponentInspection Missing() =>
            new(false, true, false, default, null, null);

        public static ComponentInspection Invalid(string code, string message) =>
            new(false, false, false, default, code, message);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFileAttributesW(string lpFileName);
}
